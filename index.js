import dotenv from 'dotenv';
dotenv.config();
import express from 'express';
import cors from 'cors';
import connectDb from './src/configs/db.js';
import router from './src/routes/index.js';

const app = express();
const port = process.env.PORT;

//Connect database
connectDb();

// Middlewares
app.use(cors());
app.use(express.urlencoded({ extended: true }));

// Routes init
app.use('/api/v1', router);

app.listen(port, () => {
    console.log('Server is running at ' + port);
});
