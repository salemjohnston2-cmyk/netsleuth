import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import healthRoutes from './routes/health';
import scanRoutes from './routes/scan';
import { startWorker } from './services/worker';
import { greet, NETSLEUTH_VERSION } from '@netsleuth/core';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

app.use('/health', healthRoutes);
app.use('/scan', scanRoutes);

app.get('/', (req, res) => {
  res.json({ message: greet(), version: NETSLEUTH_VERSION });
});

app.listen(PORT, () => {
  console.log(`🚀 NetSleuth Backend running`);
  startWorker(); // Start the background queue processor
});
