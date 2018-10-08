import {ClamScanService} from '../utils/clam-scan-service';
import {S3Utils, S3Event} from '../../node_modules/lambda-node-utils/src/s3-utils';
import {saveItem, generateDynamoDbItem} from '../../node_modules/lambda-node-utils/src/dynamodb-utils';
import {FileUploadDynamoDbMetaData, FileUploadS3MetaData} from '../file-upload-metadata';

const KB = 1000;
const MB = 1000 * KB;
const GB = 1000 * MB;
const MAXIMUM_SCANNABLE_SIZE = 200 * MB;
const MAXIMUM_FILE_SIZE = 3 * GB;
// let virusDefinitionsDownloaded;

interface ObjectCreatedResult {
    dynamoDbRecord?: FileUploadDynamoDbMetaData;
    metadata: FileUploadS3MetaData;
    bucket: string;
    key: string;
    virusScanResult: string | boolean;
}


export class S3ObjectCreatedHandler {
    private clamScanService: ClamScanService;
    private s3Utils: S3Utils;
    private dynamoDbTableName: string;

    constructor(private envConfig: any, private s3: AWS.S3, private dynamoDb: AWS.DynamoDB) {
        this.s3Utils = new S3Utils(s3);
        this.clamScanService = new ClamScanService(envConfig.clamAvHost, s3, this.s3Utils);
        this.dynamoDbTableName = envConfig.dynamoDbTableName;
    }

    /**
     * Files that are 200MB take about 1 minute to scan
     * @param event
     * @returns {Promise<any>}
     */
    async handleEvent(event: S3Event) {
        console.info('--------------------handleEvent:', event);

        let promisedUpdateFromS3;
        if (!(event as any).skipS3Download) {
console.info('updating from S3...');
            promisedUpdateFromS3 = this.clamScanService.updateDefsFromS3(this.envConfig.s3Bucket).then(async results => {
                if (results === 0) {
                    console.info('No virus definitions downloaded from S3, run freshclam & update S3 first...');
                    // whether we're servicing a ping from CloudWatch or a Records event from S3 we need to run freshclam
                    // ...but not again upon resolution
                    await this.handleEvent({skipS3Download: true} as any);
                } else {
                    console.info('updated', results, 'files from S3');
                }
                return results;
            });
        }

        if (event.Records) {
            console.info('S3ObjectCreatedHandler.handle()', event.Records.length, 'events');

            return Promise.all(event.Records.map(async (record) => {
                let bucket = record.s3.bucket.name,
                    key = record.s3.object.key,
                    result;

                console.info(record.eventName, record.s3.object);

                try {
                    result = await this.initMetadata(bucket, key);
                    await this.updateUploadStatus(result, 'processing');
                    await this.processUploadedFile(bucket, key, promisedUpdateFromS3, result);
                    await this.processObjectCreatedResult(result);
                } catch (err) {
                    console.info('Failed to process S3 record:', err);
                    await this.updateUploadStatus(result, 'error', 'System error');
                    throw err;
                }
            }));
        } else {
            if (promisedUpdateFromS3) {
                if (0 === await promisedUpdateFromS3) {
                    // would have already called `handleEvent({skipS3Download: true})`
                    return;
                }
            }

            await this.clamScanService.updateDefsFromFreshclam();
            await this.clamScanService.updateDefsToS3(this.envConfig.s3Bucket);
        }

console.info('--------end of handleEvent');
    }

    private async initMetadata(bucket: string, key: string): Promise<ObjectCreatedResult> {
        let fileHead = await this.s3Utils.getFileHead(bucket, key, true)
        let result: ObjectCreatedResult = {
            metadata: fileHead.metadata,
            bucket: bucket,
            key: key,
            virusScanResult: false
        };

        // cucumber tests "cheat" by adding "file-size" metadata
        if (!fileHead.metadata['file-size']) {
            fileHead.metadata['file-size'] = fileHead.size;
        }

        result.dynamoDbRecord = await this.createMetadataRecord(bucket, key, fileHead.metadata);
        return result;
    }

    private createMetadataRecord(bucket: string, key: string, s3Metadata: FileUploadS3MetaData): FileUploadDynamoDbMetaData {
        console.info('createMetadataRecord():', bucket, key, s3Metadata);
        const now = Date.now(),
            // as per FileExpirationDays in file-upload-s3-bucket.yaml, set to 15 days to prevent errors
            // when resources are removed before the MySQL records
            inTwoWeeks = now + (15 * 24 * 60 * 60 * 1000);

        const metadata = {
            object_bucket: bucket,
            object_key: key,
            upload_status: 'processing',
            virus_status: 'unknown',
            modified_datetime: now,
            ttl: inTwoWeeks
        };

        // copy service, user-id and any other application-specific metadata
        for (let key in s3Metadata) {
            if (key == 'qqfilename') {
                metadata['file_name'] = decodeURIComponent(s3Metadata[key]);
            } else {
                metadata[key.replace(/-/g, '_')] = s3Metadata[key];
            }
        }

        return metadata as FileUploadDynamoDbMetaData;
    }

    private async processUploadedFile(bucket: string, key: string, promisedUpdateFromS3: Promise<any>, result: ObjectCreatedResult): Promise<ObjectCreatedResult> {
        let fileSize = result.dynamoDbRecord.file_size;

        if (fileSize >= MAXIMUM_FILE_SIZE) {
            // return this.updateUploadStatus(result, 'error');
            console.info(key, 'must be less than 3GB');
            await this.deleteFileWithError(result, 'File must be less than 3GB');
        } else if (fileSize <= MAXIMUM_SCANNABLE_SIZE) {
            console.info(key, 'must be scanned for viruses', promisedUpdateFromS3);
            await promisedUpdateFromS3;
            let virusName = await this.scanForVirus(bucket, key, fileSize);
            result.virusScanResult = virusName;
        } else {
            console.info(key, 'is too large to virus scan, but small enough to accept');
        }
        return result;
    }

    private processObjectCreatedResult(result: ObjectCreatedResult): any | Promise<any> {
        if (result.virusScanResult) {
            console.info('Virus found:', result.virusScanResult);
            result.dynamoDbRecord.virus_status = 'infected';

            return this.deleteFileWithError(result, 'File contains a virus');
        } else {
            if (result.virusScanResult !== false) {
                console.info('No virus detected');
                result.dynamoDbRecord.virus_status = 'clean';
            } // otherwise the file was too large to be scanned

            return this.updateUploadStatus(result, 'complete');
        }
    }

    /**
     * @param bucket eg: 'file-uploads-dev'
     * @param key eg: 'e84c17fb-c449-48ab-9c67-f4d80a73eb91'
     * @param fileSize
     * @returns {IThenable<string>} - resolves with a virus name if infected, otherwise null
     */
    scanForVirus(bucket: string, key: string, fileSize: number) {
        return this.clamScanService.scanS3ObjectForVirus(bucket, key, fileSize);
    }

    private async updateUploadStatus(objectCreatedResult: ObjectCreatedResult, uploadStatus: string, message?: string) {
        objectCreatedResult.dynamoDbRecord.upload_status = uploadStatus;
        if (message) {
            objectCreatedResult.dynamoDbRecord.error = message;
        }
        await saveItem(this.dynamoDb, this.dynamoDbTableName, generateDynamoDbItem(objectCreatedResult.dynamoDbRecord));
        return objectCreatedResult;
    }

    private deleteFileWithError(result: ObjectCreatedResult, error: string) {
        console.info('Deleting file', result.key, 'because of error:', error);
        return Promise.all([
            this.updateUploadStatus(result, 'error', error),
            this.s3Utils.deleteFile(result.bucket, result.key)
        ]).then(() => {
            // nothing else to do
            throw error;
        });
    }
}
