const mysql = require('mysql2');

// connection pool (recommended)
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'uberpool'
});

module.exports = pool.promise();