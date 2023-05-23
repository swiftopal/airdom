const express = require('express');
const dns = require('dns');
const rateLimit = require('express-rate-limit');

const app = express();
const port = 3000;

app.use(express.static('src'));

// Rate limit middleware to prevent abuse
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // Maximum number of requests allowed in 1 minute
});

// Apply the rate limiter to all requests
app.use(limiter);

// API endpoint to validate email features
app.get('/validate-email', async (req, res) => {
  const domain = req.query.domain;

  try {
    const [dmarc, spf, dkim, mtaSts, tls, mx] = await Promise.all([
      queryDMARC(domain),
      querySPF(domain),
      queryDKIM(domain),
      queryMTASTS(domain),
      queryTLS(domain),
      queryMX(domain),
    ]);

    const validationResults = {
      hasDMARC: !!dmarc,
      hasSPF: !!spf,
      hasDKIM: !!dkim,
      hasMTASTS: !!mtaSts,
      hasTLS: !!tls,
      hasMX: !!mx,
      dmarc: dmarc || '',
      spf: spf || '',
      dkim: dkim || '',
      mtaSts: mtaSts || '',
      tls: tls || '',
      mx: mx || '',
      dmarcRecommendation: assessDMARC(dmarc),
      spfRecommendation: assessSPF(spf),
      dkimRecommendation: assessDKIM(dkim),
      mtaStsRecommendation: assessMTASTS(mtaSts),
      tlsRecommendation: assessTLS(tls),
      mxRecommendation: assessMX(mx),
    };

    res.json(validationResults);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Function to query DMARC record
function queryDMARC(domain) {
  return new Promise((resolve, reject) => {
    dns.resolveTxt('_dmarc.' + domain, (err, records) => {
      if (err) {
        if (err.code === 'ENOTFOUND') {
          resolve(null);
        } else if (err.code === 'ENODATA') {
          // No TXT records found for DMARC configuration
          resolve('');
        } else {
          reject(err);
        }
      } else {
        resolve(records[0] ? records[0].join('') : null);
      }
    });
  });
}

// Function to query SPF record
function querySPF(domain) {
  return new Promise((resolve, reject) => {
    dns.resolveTxt(domain, (err, records) => {
      if (err) {
        if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') {
          resolve(null); // Resolve with null for ENOTFOUND and ENODATA errors
        } else {
          reject(err);
        }
      } else {
        resolve(records[0] ? records[0].join('') : null);
      }
    });
  });
}

// Function to query DKIM record
function queryDKIM(domain) {
  return new Promise((resolve, reject) => {
    dns.resolveTxt('default._domainkey.' + domain, (err, records) => {
      if (err) {
        if (err.code === 'ENOTFOUND') {
          resolve(null);
        } else if (err.code === 'ENODATA') {
          // No TXT records found for DKIM configuration
          resolve('');
        } else {
          reject(err);
        }
      } else {
        resolve(records[0] ? records[0].join('') : null);
      }
    });
  });
}

// Function to query MTA-STS record
function queryMTASTS(domain) {
  return new Promise((resolve, reject) => {
    dns.resolveTxt('_mta-sts.' + domain, (err, records) => {
      if (err) {
        if (err.code === 'ENOTFOUND') {
          resolve(null);
        } else if (err.code === 'ENODATA') {
          // No TXT records found for MTA-STS configuration
          resolve('');
        } else {
          reject(err);
        }
      } else {
        resolve(records[0] ? records[0].join('') : null);
      }
    });
  });
}

// Function to query TLS record
function queryTLS(domain) {
  return new Promise((resolve, reject) => {
    dns.resolveTxt('_smtp._tls.' + domain, (err, records) => {
      if (err) {
        if (err.code === 'ENOTFOUND') {
          resolve(null);
        } else if (err.code === 'ENODATA') {
          // No TXT records found for TLS configuration
          resolve([]);
        } else {
          reject(new Error('Failed to query TLS records: ' + err.message));
        }
      } else {
        resolve(records[0] ? records[0].join('') : null);
      }
    });
  });
}
// Function to query MX record
function queryMX(domain) {
  return new Promise((resolve, reject) => {
    dns.resolveMx(domain, (err, addresses) => {
      if (err) {
        if (err.code === 'ENOTFOUND') {
          resolve(null);
        } else if (err.code === 'ENODATA') {
          // No MX records found for the domain
          resolve([]);
        } else {
          reject(err);
        }
      } else {
        resolve(addresses[0] ? addresses[0].exchange : null);
      }
    });
  });
}

// Function to assess the quality of DMARC configuration
function assessDMARC(dmarc) {
  if (!dmarc || dmarc.length === 0) {
    // DMARC record doesn't exist or is empty
    return "<p style='color:red!important;font-weight:bold;'>No DMARC Configuration ❌</p>";
  }

  const dmarcPolicy = getDMARCPolicy(dmarc);
  const dmarcAlignment = getDMARCAlignment(dmarc);
  const subdomainPolicy = hasSubdomainPolicy(dmarc);
  const reportingValid = isReportingValid(dmarc);

  let assessment = "DMARC Configuration: Unknown";

  if (dmarcPolicy === "none") {
    assessment = "DMARC Configuration: None ";
  } else if (dmarcPolicy === "quarantine") {
    assessment = "DMARC Configuration: Quarantine ✔️";
  } else if (dmarcPolicy === "reject") {
    assessment = "DMARC Configuration: Reject ✔️";
  } else {
    assessment = "<p style='color:red!important;font-weight:bold;'>Invalid DMARC Configuration ❌</p>";
  }

  if (dmarcAlignment === "strict") {
    assessment += ", Strict Alignment";
  } else if (dmarcAlignment === "relaxed") {
    assessment += ", Relaxed Alignment";
  }

  if (subdomainPolicy) {
    assessment += ", Subdomain Policy";
  }

  if (reportingValid) {
    assessment += ", Reporting Valid";
  }

  return assessment;
}

// Function to get the DMARC policy from DMARC record
function getDMARCPolicy(dmarc) {
  const policyRegex = /p=([a-z]+)/i;
  const matches = dmarc.match(policyRegex);
  return matches ? matches[1].toLowerCase() : null;
}

// Function to check if DMARC record has subdomain policy
function hasSubdomainPolicy(dmarc) {
  return /sp=([a-z]+)/i.test(dmarc);
}

// Function to check if DMARC record has reporting valid flag
function isReportingValid(dmarc) {
  return /rf=afrf/i.test(dmarc);
}

// Function to get the DMARC alignment from DMARC record
function getDMARCAlignment(dmarc) {
  const alignmentRegex = /adkim=([a-z]+)/i;
  const matches = dmarc.match(alignmentRegex);
  return matches ? matches[1].toLowerCase() : null;
}

// Function to assess the quality of SPF configuration
function assessSPF(spf) {
  if (!spf || spf.length === 0) {
    // SPF record doesn't exist or is empty
    return "<p style='color:red!important;font-weight:bold;'>No Configuration found ❌</p>";
  }

  if (spf.includes('v=spf1')) {
    return "<p style='color:green!important;font-weight:bold;'>SPF Configuration is found ✅</p>";
  }

  return "<p style='color:red!important;font-weight:bold;'>❌ Invalid SPF Configuration found. You can browse online on how to setup or improve your SPF Configuration</p>";
}

// Function to assess the quality of DKIM configuration
function assessDKIM(dkim) {
  if (!dkim || dkim.length === 0) {
    // DKIM record doesn't exist or is empty
    return "<p style='color:red!important;font-weight:bold;'>❌ No DKIM Configuration found. You can use tool like <a href='https://easydmarc.com/tools/dkim-record-generator' target='_blank' style='color:green!important;'>EASY DMARC</a> to improve your DKIM Configuration</p>";
  }

  if (dkim.includes('v=DKIM1')) {
    return "<p style='color:green!important;font-weight:bold;'>Valid DKIM Configuration found ✅</p>";
  }

  return "<p style='color:red!important;font-weight:bold;'>❌ Invalid DKIM Configuration found. You can use tool like <a href='https://easydmarc.com/tools/dkim-record-generator' target='_blank' style='color:green!important;'>EASY DMARC</a> to improve your DKIM Configuration</p>";
}

// Function to assess the quality of MTA-STS configuration
function assessMTASTS(mtaSts) {
  if (!mtaSts || mtaSts.length === 0) {
    // MTA-STS record doesn't exist or is empty
    return "<p style='color:red!important;'>❌ No MTA-STS Configuration. Please make sure you have the proper MTA-STS setup in your DNS record.</p>";
  }

  if (mtaSts.includes('v=STSv1')) {
    return "<p style='color:green!important;font-weight:bold;'>MTA-STS Configuration is found ✅</p>";
  }

  return "<p style='color:red!important;font-weight:bold;'>❌ Invalid MTA-STS Configuration</p>";
}

// Function to assess the quality of TLS configuration
function assessTLS(tls) {
  if (!tls || tls.length === 0) {
    // TLS record doesn't exist or is empty
    return "<p style='color:red!important;font-weight:bold;'>❌ No TLS Configuration found. You can use tool like <a href='https://www.checktls.com/TestReceiver' target='_blank' style='color:green!important;'>CHECKTLS</a> to improve your TLS</p>";
  }

  if (tls.includes('v=TLSRPT') && tls.includes('rua=')) {
    return "<p style='color:green!important;font-weight:bold;'>Valid TLS Configuration ✅</p>";
  }

  return "<p style='color:red!important;font-weight:bold;'>❌ Invalid TLS Configuration. You can use tool like <a href='https://www.checktls.com/TestReceiver' target='_blank' style='color:green!important;'>CHECKTLS</a> to improve your TLS</p>";
}


// Function to assess the quality of MX configuration
function assessMX(mx) {
  if (!mx || mx.length === 0) {
    // MX record doesn't exist or is empty
    return "<p style='color:red!important;font-weight:bold;'>No MX Configuration ❌</p>";
  }

  if (mx.length > 0) {
    // MX record exists
    return "<p style='color:green!important;font-weight:bold;'>MX Configuration is found ✅</p>";
  }

  return "<p style='color:red!important;font-weight:bold;'>Invalid MX Configuration ❌</p>";
}

// Start the server
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
