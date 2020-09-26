import winston from 'winston';

export const logger = winston.createLogger({
  level: process.env.SMR_VERIFIER_DEBUG ? 'debug' : 'info',
  format: winston.format.simple(),
  transports: [
    new winston.transports.File({ filename: 'smrversionverifier.log' }),
    new winston.transports.Console(),
  ],
});
