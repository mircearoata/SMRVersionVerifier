import got, { Response } from 'got';
import FormData from 'form-data';
import { VTAuthorization } from '../config.json';
import { sleep, setIntervalImmediate } from './util';
import { logger } from './logging';

export interface VTRequest {
  endpoint: string;
  method?: 'GET' | 'POST';
  body?: string | Buffer | FormData
}

const VT_API_URL = 'https://www.virustotal.com/api/v3';
const RATE_LIMIT = 240;
const RATE_LIMIT_PERIOD = 60 * 60; // seconds

interface VTRequestQueueEntry<T> {
  request: VTRequest;
  resolve: (value?: {
      data: T;
  } | PromiseLike<{
      data: T;
  }> | undefined) => void;
  reject: (error: Error | string) => void;
}

const requestQueue: VTRequestQueueEntry<never>[] = [];

async function sendRequest(request: VTRequest): Promise<Response<string>> {
  let url = '';
  if (request.endpoint.includes('virustotal.com')) {
    url = request.endpoint;
  } else {
    url = `${VT_API_URL}${request.endpoint}`;
  }
  return got(url, {
    method: request.method || 'GET',
    body: request.body,
    headers: {
      'x-apikey': VTAuthorization,
    },
  });
}

async function executeRequest(request: VTRequestQueueEntry<never>): Promise<void> {
  logger.debug(`Processing VT request ${request.request.endpoint}`);
  try {
    const response = await sendRequest(request.request);
    request.resolve(JSON.parse(response.body));
  } catch (e) {
    logger.error(e);
    if (e.name === 'HTTPError') {
      logger.error(e.response.body);
    }
    request.reject(e);
  }
}

async function processRequests() {
  logger.debug('Processing batch of VT requests');
  let run = true;
  setTimeout(() => { if (run) { run = false; logger.debug('Batch of VT requests timed out'); } }, RATE_LIMIT_PERIOD * 1000);
  for (let i = 0; i < RATE_LIMIT && run; i += 1) {
    let request = requestQueue.shift();
    while (run && !request) {
      request = requestQueue.shift();
      await sleep(0.000001);
    }
    if (request) {
      executeRequest(request);
    }
  }
  run = false;
  logger.debug('Finished processing batch of VT requests');
}

export async function queueRequest<T>(request: VTRequest): Promise<{data: T}> {
  logger.debug(`Queuing VT request ${request.endpoint}`);
  return new Promise((resolve, reject) => {
    requestQueue.push({
      request,
      resolve,
      reject,
    });
  });
}

setIntervalImmediate(processRequests, RATE_LIMIT_PERIOD * 1000);
