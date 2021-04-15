import FormData from 'form-data';
import { writeFileSync } from 'fs';
import got, { HTTPError } from 'got/dist/source';
import JSZip from 'jszip';
import path from 'path';
import { performance } from 'perf_hooks';
import { logger } from './logging';
import { SMR_API_URL, SMRModVersion } from './smr';
import { ensureExists, sleep } from './util';
import { queueRequest } from './virustotal';

/**
 * @param fileBuffer
 * @param scanFileName
 * @param outputFileName
 */
async function verifyFile(fileBuffer: Buffer, scanFileName: string, outputFileName: string): Promise<boolean> {
  const t0 = performance.now();
  const uploadURL = (await queueRequest<string>({
    endpoint: '/files/upload_url',
    method: 'GET',
  })).data;

  const form = new FormData();
  form.append('file', fileBuffer, { filename: scanFileName });

  const submissionID = (await queueRequest<{id: string}>({
    endpoint: uploadURL,
    method: 'POST',
    body: form,
  })).data.id;
  const t1 = performance.now();

  logger.info(`Uploaded ${scanFileName} to VT. (Took ${t1 - t0}ms)`);

  let firstCheck = true;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const result = (await queueRequest<{
      attributes: {
        status: string,
        stats: {
          suspicious: number,
          malicious: number,
        }
      }
    }>({
      endpoint: `/analyses/${submissionID}`,
      method: 'GET',
    }));
    if (result.data.attributes.status === 'completed') {
      ensureExists(`scanResults/${path.dirname(outputFileName)}`);
      writeFileSync(`scanResults/${outputFileName}.json`, JSON.stringify(result, null, 2));
      return result.data.attributes.stats.suspicious === 0
          && result.data.attributes.stats.malicious === 0;
    }
    await sleep(firstCheck ? 20 : 5); // wait more if the first check fails, as the file is a new one for VT
    firstCheck = false;
  }
}

const MAX_DOWNLOAD_ATTEMPTS = 20;
const DOWNLOAD_ATTEMPT_INTERVAL = 5;

export async function verifyVersion(version: SMRModVersion): Promise<boolean> {
  let file = null;
  let attempt = 0;
  const t0 = performance.now();
  while (!file) {
    try {
      file = await got(`${SMR_API_URL}${version.link}`, { responseType: 'buffer' }).buffer();
    } catch (e) {
      if (e instanceof HTTPError && (e as HTTPError).response.statusCode === 400) {
        attempt += 1;
        if (attempt === MAX_DOWNLOAD_ATTEMPTS) {
          throw e;
        }
      } else {
        throw e;
      }
    }
    await sleep(DOWNLOAD_ATTEMPT_INTERVAL);
  }
  const t1 = performance.now();
  logger.info(`Downloaded ${version.mod_id}@${version.version} (${version.id}). (Took ${t1 - t0}ms)`);

  const verify = [];

  const zip = await JSZip.loadAsync(file);

  verify.push(...zip.filter((relPath, f) => path.extname(f.name) === '.dll')
    .map(async (objectFile) => {
      try {
        return verifyFile(await objectFile.async('nodebuffer'), `${version.id}_${objectFile.name}`, `${version.mod_id}/${version.version}_${version.id}/${objectFile.name}`);
      } catch (e) {
        logger.error(e);
        return false;
      }
    }));

  return (await Promise.all(verify)).every((a) => a);
}
