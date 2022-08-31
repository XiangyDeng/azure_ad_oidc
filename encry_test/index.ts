// var express = require('express');
// import * as crypto from "crypto";
// var app = express();

// app.get('/', (res, rep) => {
//     key: Buffer;

//     const decipher = crypto.createDecipheriv("aes-256-cbc", "4uGh1q8y2DYryJwrVMHs0kWXJlqvHWWt", new Buffer("Ux+RWZlJnaE88Ndm8NXwPQ==", "base64"));
//     let decrypted = decipher.update(new Buffer("kfAIPVM3JlqKjKaQr5zoU3Ym2A8OPJ9K0xqxtU/cteOpWOLfH97QUxP+tt2a2upVa5x4vt7H6acZZeN9MvEIyvEBVU3i9qynTeWY5vyVUQpNc4B7VGgnTrX1tedZ4qvXyPZcA/asCmHa3hbvzIjosrAQubb8w4kmv5rdpacunsQXM8zu3jzyNi5kss0kVwfhaUcB5sPZe7yVp6TLEJd5qFIbvHFkCGtz/bCSEYRjdxHIrD6eu8S9TNYRcyFT0KT5Pa5PXJ8rRwR3of9MdCgPuMFEFozQ4FhmgVg/kPEww7PbozNYExphTZH12xO8MUgZAA9khmr0/EbDTwNW1HCVGyYQXJuvGB9fZ62mb9ZPH1g3k5cEtrxfOP3dhkoRLkwAomE9M2Yccn2e4yzDOjog0L2/Jzh50wJbR7zw79dxaw05KQB3LITFK/KlDMOVigtqltErC0MwbfzPaOJM8gYZZ/jRkxb+leg+6PkaGaUV/G/tS8oSUhiZ1BhDLfSzLXrP1CnhwoAFsRp5W5KHoI0V+YWqOuSsNk5dyIj8Dr68DHs=", "base64"));
//     const finalDecrypted = Buffer.concat([decrypted, decipher.final()]);
//     return finalDecrypted.toString("utf8");

//     rep.send('Hello, word!');
// });

// app.listen(3000);.

import express from 'express';

const app = express();
const PORT = 3000;

app.get('/', (req, res) => {
  res.send('Hello world');
});

app.listen(PORT, () => {
  console.log(`Express with Typescript! http://localhost:${PORT}`);
});