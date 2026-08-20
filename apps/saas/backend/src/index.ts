import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import healthRoutes from './routes/health';
import { runScan, greet, NETSLEUTH_VERSION } from '@netsleuth/core';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

app.use('/health', healthRoutes);

// Test scan route
app.get('/scan/:domain', async (req, res) => {
  try {
    const domain = req.params.domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    const results = await runScan(domain);
    res.json(results);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/', (req, res) => {
  res.json({
    message: greet(),
    version: NETSLEUTH_VERSION
  });
});

app.listen(PORT, () => {
  console.log(`🚀 NetSleuth Backend running`);
});
