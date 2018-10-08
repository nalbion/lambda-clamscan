import {S3} from 'aws-sdk';
const crypto = require('crypto');
const fs = require('fs');
const stream = require('stream');
// const clamav = require('clamav.js');
const clamav = require('./clamav');
import {S3Utils, S3Event} from '../../node_modules/lambda-node-utils/src/s3-utils';
import {PutObjectRequest} from 'aws-sdk/clients/s3';
import {exec, spawn} from 'child_process';

const KB = 1024;
const MB = 1024 * KB;
const CHUNK_SIZE = 2 * MB;

export const AV_DEFINITION_PREFIX = 'clamav_defs/';
const AV_DEFINITION_PATH = '/tmp/' + AV_DEFINITION_PREFIX;
const AV_DEFINITION_FILENAMES = ['bytecode.cvd', 'daily.cvd', 'main.cvd'];
            //, 'daily.cld', 'main.cld'];
            //, 'daily.cud', 'bytecode.cud'];

interface ClamAvScanner {
    port: number;
    host: string;
    scan(object: string|NodeJS.ReadableStream, callback: (err: Error, object?: string|NodeJS.ReadableStream, result?: string) => void);
}

/* tslint:disable */
/**
 * @see https://catsagj.atlassian.net/wiki/display/OLC/ClamAV+Anti-Virus
 * @see https://bitbucket.org/catsagj/online-courts-ui-core/src/551ddc85cabfc5f1e47bbc95cf334f8abc57aeb8/src/main/java/au/gov/nsw/lawlink/onlineregistry/clamav/ClamScanService.java?at=master&fileviewer=file-view-default
 * @see https://engineering.upside.com/s3-antivirus-scanning-with-lambda-and-clamav-7d33f9c5092e
 */
/* tslint:enable */
export class ClamScanService {
    constructor(private clamAvHost: string, private s3: AWS.S3, private s3Utils: S3Utils) {
    }

    /**
     * @param bucket
     * @param key
     * @param fileSize
     * @returns {IThenable<T>} resolves with the name of the virus if found, otherwise null for a clean file
     */
     scanS3ObjectForVirus(bucket: string, key: string, fileSize?: number): Promise<string> {
        console.info('Scanning', key, 'for viruses...');
        return this.downloadFile(bucket, key, fileSize).then(localPath => this.scanFile(localPath));
    }

    /**
     * @param {string} bucket - the bucket in which virus definitions are cached
     * @param {string} prefix - the S3 prefix (directory) applied to virus definition files
     * @returns {Promise<number>} resolves with the number of virus definition files downloaded from S3
     */
    updateDefsFromS3(bucket: string, prefix: string = AV_DEFINITION_PREFIX): Promise<number> {
        console.info('Updating virus definitions from S3', bucket, prefix);
        return Promise.all(AV_DEFINITION_FILENAMES.map(async fileName => {
            const key = prefix + fileName;
            const localPath = AV_DEFINITION_PATH + fileName;
            try {
                const s3Md5 = await this.getMd5FromS3(bucket, key);
                if (s3Md5 === null) {
                    console.info(fileName, 'does not exist in S3');
                    return 0;
                } else if (!fs.existsSync(localPath)) {
                    // try {
                    //     fs.mkdirSync(AV_DEFINITION_PATH, '755');
                    // } catch (err) {
                    //     // probably EEXIST
                    // }
                    console.info(fileName, 'has not been downloaded from S3, downloading now');
                } else {
                    const fileMd5 = await this.getMd5FromFile(localPath);
                    if (fileMd5 !== s3Md5) {
                        console.info(fileName, 'has been updated in S3, downloading updated version', fileMd5, s3Md5);
                    } else {
                        console.info(fileName, 'is already up to date, skip download');
                        return 1;
                    }
                }
                console.info('Downloading definition file', bucket, key);
                await this.downloadFile(bucket, key, await this.s3Utils.getFileSize(bucket, key), localPath);
                return 1;
            } catch (err) {
                console.info('failed to download', fileName, err);
                return 0;
            }
        })).then(results => {
            return results.reduce((total, result) => total + result, 0);
        });
    }

    /**
     * @param {string} bucket - the bucket in which virus definitions are cached
     * @param {string} prefix - the S3 prefix (directory) applied to virus definition files
     * @returns {Promise<[void]>}
     */
    updateDefsToS3(bucket: string, prefix: string = AV_DEFINITION_PREFIX) {
        console.info('Uploading virus definitions to S3');
        return Promise.all(AV_DEFINITION_FILENAMES.map(async fileName => {
            const key = prefix + fileName;
            const localPath = AV_DEFINITION_PATH + fileName;
            if (fs.existsSync(localPath)) {
                const localMd5 = await this.getMd5FromFile(localPath);
                if (localMd5 !== await this.getMd5FromS3(bucket, key)) {
                    console.info('Uploading definition file', bucket, key);
                    await this.uploadFile(localPath, bucket, key);
                    await this.updateMd5InS3(bucket, key, localMd5);
                }
            }
        }));
    }

    /**
     * This takes about 25 seconds (with 2GB RAM allocated on Lambda). Uses 529MB.
     * @param {string} path
     * @returns {Promise<number>} resolves with 1 if definitions updated, otherwise 0
     */
    updateDefsFromFreshclam(path: string = AV_DEFINITION_PATH): Promise<number> {
        console.info('Updating virus definitions from freshclam');
        return new Promise(function(resolve, reject) {
            if (!fs.existsSync('/tmp/freshclam')) {
                console.info('Installing freshclam...');
                if (!fs.existsSync(path)) {
                    fs.mkdirSync(path);
                }
                fs.copyFileSync('/var/task/lib/freshclam', '/tmp/freshclam');
                fs.chmodSync('/tmp/freshclam', '755');
                console.info('Freshclam installed');
            }

            try {
                console.info('Running freshclam...', path);

                const freshclam = spawn('/tmp/freshclam',
                                        [
                                            '--config-file=/var/task/lib/freshclam.conf',
                                            '-v',
                                            '-u', require('os').userInfo().uid,
                                            '--datadir=' + path
                                        ],
                                        {stdio: 'inherit'});

                freshclam.on('error', reject);
                freshclam.on('exit', function(code, signal) {
                    if (code == 1) {
                        console.info('Freshclam has updated virus definitions');
                    } else if (code > 1 || (signal && signal !== 'SIGKILL')) {
                        reject(new Error('freshclam exited with code ' + code));
                    } else {
                        console.info('Freshclam did not need to update virus definitions');
                        resolve();
                    }
                });
            } catch (err) {
                console.info('Failed to run freshclam', err);
                reject(err);
            }
        });
    }

    /**
     * @param {string} path
     * @returns {Promise<any>} resolves with 1 if file is infected
     */
    scanFile(path: string) {
        return new Promise(function(resolve, reject) {
            if (!fs.existsSync('/tmp/clamscan')) {
                console.info('installing clamscan...');
                if (!fs.existsSync(path)) {
                    fs.mkdirSync(path);
                }
                fs.copyFileSync('/var/task/lib/clamscan', '/tmp/clamscan');
                fs.chmodSync('/tmp/clamscan', '755');
                console.info('clamscan installed');
            }

            console.info('Scanning:', path);
            const slash = AV_DEFINITION_PATH.lastIndexOf('/');
            const defDir = AV_DEFINITION_PATH.substr(0, slash);

            console.info(defDir, 'contents:', fs.readdirSync(defDir));

            const clamscan = spawn(//'ls', ['-al', '/tmp/clamav_defs'],
                                    '/tmp/clamscan',
                                    ['-v', '-a', '--stdout', '--tempdir=/tmp', '-d ' + defDir, path],
                                    {stdio: 'inherit'});
            clamscan.on('error', reject);
            clamscan.on('exit', function(code, signal) {
                if (code === 1) {
                    return reject('Virus detected');
                } else if (code > 0 || signal) {
                    return reject(code || signal);
                }
                console.info('clamscan close:', code);
                resolve(code);
            });
        });
    }

    private getMd5FromFile(fileName: string): Promise<string> {
        return new Promise((resolve, reject) => {
            fs.createReadStream(fileName).pipe(crypto.createHash('md5').setEncoding('hex'))
                .on('error', reject)
                .on('finish', function() {
                    resolve(this.read());
                });
        });
    }

    private getMd5FromS3(bucket: string, key: string): Promise<string> {
        return new Promise((resolve, reject) => {
            this.s3.getObjectTagging({Bucket: bucket, Key: key}, function (err, data: S3.Types.GetObjectTaggingOutput) {
                if (err) {
                    // If not found, S3 will throw NotFound {code: 'NoSuchKey', statusCode: 404}
                    console.info('Failed to get S3 tags for', key, err.statusCode, err);
                    if (err.statusCode === 404) {
                        resolve(null);
                    } else {
                        reject(err);
                    }
                } else {
                    let i = data.TagSet.length;
                    while (i-- !== 0) {
                        const tag = data.TagSet[i];
                        if (tag.Key === 'md5') {
                            return resolve(tag.Value);
                        }
                    }
                    console.info('!No md5 tag found for', key);
                    resolve(null);
                }
            });
        });
    }

    private updateMd5InS3(bucket: string, key: string, md5: string): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            this.s3.putObjectTagging({Bucket: bucket, Key: key, Tagging: {TagSet: [{Key: 'md5', Value: md5}]}}, function (err) {
                if (err) {
                    // If not found, S3 will throw NotFound {message: null, code: 'NotFound', statusCode: 404}
                    reject(err);
                } else {
                    resolve();
                }
            });
        });
    }

    private uploadFile(localPath: string, bucket: string, key: string) {
        return new Promise((resolve, reject) => {
            fs.readFile(localPath, (err, data) => {
                if (err) {
                    return reject(err);
                }

                const params: PutObjectRequest = {
                    Bucket: bucket,
                    Key: key,
                    Body: new Buffer(data, 'binary')
                };

                this.s3.putObject(params, (err, data) => {
                    if (err) {
                        console.info('Failed to upload', key, 'to S3 bucket', bucket);
                        reject(err);
                    } else {
                        resolve(data);
                    }
                });
            });
        });
    }

    /**
     * @param {string} bucket
     * @param {string} key
     * @param {number} fileSize
     * @param {string} localPath
     * @returns {Promise<string>} resolves with the localPath of the downloaded file
     */
    private downloadFile(bucket: string, key: string, fileSize: number, localPath = '/tmp/' + bucket + '/' + key): Promise<string> {
        const params = {Bucket: bucket, Key: key, Range: null};

        return new Promise((resolve, reject) => {
            let slash = localPath.lastIndexOf('/');
            if (slash > 0) {
                const dir = localPath.substr(0, slash);
                if (!fs.existsSync(dir)) {
                    console.info('mkdir', dir);
                    fs.mkdirSync(dir, '0755');
                }
            }

            if (fileSize && fileSize > CHUNK_SIZE) {
                console.info(key, 'file size:', fileSize, '> CHUNK_SIZE (' + CHUNK_SIZE + ')');
                const dataStream = fs.createWriteStream(localPath);

                let readNextChunk = (start: number) => {
                    // Range: 'bytes=0-1' gives the first 2 bytes
                    let end = Math.min(start + CHUNK_SIZE, fileSize) - 1;
                    params.Range = 'bytes=' + start + '-' + end;
                    // console.info('Reading from S3', params.Range, '(inclusive)');

                    this.s3.getObject(params, (err: Error, data) => {
                        if (err) {
                            console.info('Failed to read', key, start, end);
                            reject(err);
                        } else {
                            // console.info('writing to dataStream...');
                            dataStream.write(data.Body, err => {
                                if (err) {
                                    console.info('Failed to write', localPath);
                                    reject(err);
                                } else if (end + 1 >= fileSize) {
                                    // console.info('end datastream');
                                    dataStream.end();
                                    resolve(localPath);
                                } else {
                                    readNextChunk(end + 1);
                                }
                            });

                        }
                    });
                };

                readNextChunk(0);
            } else {
                this.s3.getObject(params, (err: Error, data) => {
                    if (err) {
                        console.info('Failed to read', key);
                        reject(err);
                    } else {
                        fs.writeFile(localPath, data.Body, err => {
                            if (err) {
                                console.info('Failed to write', localPath);
                                reject(err);
                            } else {
                                resolve(localPath);
                            }
                        });
                    }
                });
            }
        });
    }
        /*return new Promise((resolve, reject) => {
            let params = {Bucket: bucket, Key: key, Range: null};

            let doScan = (dataStream: NodeJS.ReadableStream, onConnect: (socket: Socket) => void) => {
                this.scanDataForVirus(dataStream, onConnect, (err, result) => {
                    if (err) {
                        console.info('error:', err);
                        reject(err);
                    } else {
                        // console.info('done!', result);
                        resolve(result);
                    }
                });
            };

            if (fileSize && fileSize > CHUNK_SIZE) {
                console.info('File size:', fileSize, '> CHUNK_SIZE (' + CHUNK_SIZE + ')');
                let dataStream = new stream.PassThrough({highWaterMark: CHUNK_SIZE});

                let readNextChunk = (start: number) => {
                    // Range: 'bytes=0-1' gives the first 2 bytes
                    let end = Math.min(start + CHUNK_SIZE, fileSize) - 1;
                    params.Range = 'bytes=' + start + '-' + end;
                    console.info('Reading from S3', params.Range, '(inclusive)');

                    this.s3.getObject(params, (err: Error, data) => {
                        if (err) {
                            console.info('Failed to read', key, start, end);
                            reject(err);
                        } else {
                            dataStream.write(data.Body);
                            if (end + 1 >= fileSize) {
                                // console.info('Finished sending chunks');
                                dataStream.end();
                            } else {
                                readNextChunk(end + 1);
                            }
                        }
                    });
                };

                doScan(dataStream, () => {
                    readNextChunk(0);
                });
            } else {
                this.s3.getObject(params, (err: Error, data) => {
                    if (err) {
                        reject(err);
                    } else {
                        const dataStream = this.prepareDataForClamAv(data.Body);
                        // dataStream.pause();
                        doScan(dataStream, () => {
                            // dataStream.resume();
                            // dataStream.end()
                        });
                    }
                });
            }
        });
    }*/

    /* *
     * According to the AWS docs, data.Body can be one of:
     *   Buffer, Typed Array, Blob, String, ReadableStream.
     * ClamAvScanner.scan() requires a string or ReadableStream
     * /
    prepareDataForClamAv(data: Buffer|Array<any>|Object|string|NodeJS.ReadableStream): NodeJS.ReadableStream {
        if (data.constructor != Buffer && typeof data != 'string') {
            // console.info('data is already a readable stream');
            return data as NodeJS.ReadableStream;
        } else {
            // console.info('need to create a stream:', typeof data, data.constructor == Buffer);
            // Wrap the Buffer with a stream
            let dataStream = new stream.PassThrough();
            // setTimeout(() => {
// console.info('no delay - this should fail sometimes');
// TODO: don't write (def not end) until socket connected
                dataStream.end(data);

            /*let dataStream = new stream.Readable({
                read(size) {
                    console.info('read(', size,'), from', this._offset, 'we have', this._length);
                    // return data;

                    if ( this._offset < this._length ) {
                        this.push(this._source.slice(this._offset, (this._offset + size)));
                        this._offset += size;
                    }

                    // If we've consumed the entire source buffer, close the readable stream.
                    if ( this._offset >= this._length ) {
                        this.push(null);
                    }
                }
            });
            dataStream._source = data as Buffer;
            dataStream._offset = 0;
            dataStream._length = (data as Buffer).length;* /

            // }, 1000);
            return dataStream;
        }
    }

    scanDataForVirus(data: NodeJS.ReadableStream, onConnect: (socket: Socket) => void, callback: (err: Error, result?: string) => void) {
        let scanner: ClamAvScanner = clamav.createScanner(3310, this.clamAvHost);
        const socket = scanner.scan(data, (err, object, result) => {
            console.info('scanned:', err, /*object, * /result);
            callback(err, result);
        });

        socket.on('connect', onConnect);
    }*/
}
