import { HTTPError } from 'got/dist/source';
import { performance } from 'perf_hooks';
import { smrQuery, SMRModVersion } from './smr';
import {
  formatError, setIntervalImmediate,
} from './util';
import { logger } from './logging';
import { verifyVersion } from './verify';

const verifiedVersions: string[] = [];

async function checkForUnverifiedVersions() {
  try {
    const versionQuery = await smrQuery<{
      getUnapprovedVersions: {
        versions: SMRModVersion[]
      }
    }>(`
    query {
      getUnapprovedVersions {
        versions {
          id,
          mod_id,
          version
          link,
        }
      }
    }`);
    const unapprovedVersions = versionQuery.getUnapprovedVersions.versions;

    unapprovedVersions.forEach(async (version) => {
      if (!verifiedVersions.includes(version.id)) {
        verifiedVersions.push(version.id);
        logger.info(`Verifying ${version.mod_id}@${version.version} (${version.id}).`);
        try {
          const t0 = performance.now();
          const verifyResult = await verifyVersion(version);
          const t1 = performance.now();
          logger.info(`Result of verifying ${version.mod_id}@${version.version} (${version.id}) is ${verifyResult ? 'ok' : 'bad'}. (Took ${t1 - t0}ms)`);
          if (verifyResult) {
            try {
              const alreadyApproved = (await smrQuery<{
              getVersion: {
                approved: boolean
              }
            }>(`
            query($versionId: VersionID!) {
              getVersion(versionId: $versionId) {
                approved
              }
            }`, { versionId: version.id })).getVersion.approved;
              if (alreadyApproved) {
                logger.info(`Version ${version.mod_id}@${version.version} (${version.id}) was already approved in the meantime`);
                return;
              }
              const approveQuery = await smrQuery<{
              approveVersion: boolean
            }>(`
            mutation($versionId: VersionID!) {
              approveVersion(versionId: $versionId)
            }`, { versionId: version.id });
              if (!approveQuery.approveVersion) {
                logger.error(`Failed to approve ${version.mod_id}@${version.version} (${version.id}).`);
              }
            } catch (e) {
              logger.error(`Error approving ${version.mod_id}@${version.version} (${version.id}): ${formatError(e)}.`);
            }
          } else {
            logger.info('Version should be checked manually.');
          }
        } catch (e) {
          if (e instanceof HTTPError) {
            logger.error(`Error verifying ${version.mod_id}@${version.version} (${version.id}): ${formatError(e)}\nRequest: ${((e as HTTPError).request).requestUrl}\nResponse: ${JSON.stringify((e as HTTPError).response.body)}.`);
          } else {
            logger.error(`Error verifying ${version.mod_id}@${version.version} (${version.id}): ${formatError(e)}.`);
          }
        }
      }
    });
  } catch (e) {
    logger.error(`Error checking for unapproved versions: ${formatError(e)}.`);
  }
}

logger.info('Initialized');
setIntervalImmediate(checkForUnverifiedVersions, 5 * 1000);
