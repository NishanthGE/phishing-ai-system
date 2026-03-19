/**
 * ============================================================
 *  SecureAI — Real ML Engine  v3.1  (False-Positive Fix)
 *  Naive Bayes Email Classifier + Random Forest URL Classifier
 * ============================================================
 *
 * FIX LOG (v3.1):
 *  1. Added stopword list — removes high-frequency words that
 *     appear in BOTH classes and add noise (your, account, click…)
 *  2. Deduplicated tokens per document — each word counted once
 *     per email so common words don't amplify unfairly
 *  3. Raised classification thresholds:
 *       Phishing   ≥ 72  (was 65)
 *       Suspicious ≥ 48  (was 35)
 *  4. Added 40 more legit training emails covering transactional
 *     receipts, bank statements, password-reset confirmations, and
 *     security-notification emails that previously tripped up NB
 *  5. Adjusted log-prior to favor legit class slightly (0.55)
 *     to reduce false positive rate
 */

'use strict';

/* ─────────────────────── STOPWORDS (FIX #1) ─────────────────────── */
// Words so common in BOTH classes they hurt more than they help.
// Removing them lets the model focus on truly discriminating vocabulary.
const STOPWORDS = new Set([
  // generic function words
  'the','and','for','are','but','not','you','all','can','had','her','was',
  'one','our','out','day','get','has','him','his','how','its','let',
  'may','new','now','old','own','say','she','too','use','way',
  'who','why','will','with','your','from','they','this','that','have',
  'been','were','said','each','what','when','then','than','some','into',
  'just','here','also','more','very','any','only','both','after','where',
  // ambiguous action words (equal in legit & phishing)
  'click','link','account','please','update','email','login',
  'password','access','security','information','service','user',
  'dear','valued','customer','message','sign','time','send',
  // common legit words that sometimes match phishing patterns
  'attached','below','above','review','confirm','check','view',
  'open','find','read','see','visit','use','enter','provide',
  // ── PROFESSIONAL EMAIL WORDS (FIX for cover letter / formal email FP) ──
  // salutation words
  'sir','madam','sincerely','regards','faithfully','respected',
  // self-introduction words
  'name','myself','currently','pursuing','degree','study','student',
  'year','college','university','institute','department','campus',
  // professional intent words
  'interest','interested','opportunity','experience','skills','knowledge',
  'internship','position','role','apply','application','candidate',
  'learn','develop','growth','career','professional','industry',
  'field','domain','area','sector','team','organization','company',
  // common formal phrases
  'writing','express','hope','doing','well','greatly','appreciate',
  'kindly','attached','consideration','forward','hearing','back',
  'thank','thanks','best','regards','warm','truly','yours',
  'resume','portfolio','profile','reference','recommendation',
  'able','willing','eager','passion','dedicated','motivated',
  // academic words
  'fundamental','basic','analysis','networking','research','project',
  'internship','training','practical','theoretical','course','module',
]);

/* ─────────────────────── TRAINING DATA ─────────────────────── */

// 60 PHISHING emails — focused on patterns AFTER stopword removal
const PHISHING_EMAILS = [
  "URGENT suspended compromised unauthorized suspicious fraud stolen immediately expire suspend",
  "PayPal account temporarily suspended verify information restore access immediately",
  "Final notice bank account closed 24 hours act prevent penalty",
  "Security alert unauthorized detected Update immediately or suspended",
  "Confirm credit card details billing failure immediately mandatory",
  "Microsoft account accessed unknown location secure identity now",
  "Free gift limited prize today obligation win cash lottery reward",
  "Amazon order delayed Confirm shipping address payment method here urgent",
  "Apple ID disabled restore within 24 hours click below mandatory",
  "Verify account immediately Failure result permanent suspension penalty",
  "Warning suspicious detected Confirm prevent account lockout penalty",
  "Tax refund Provide bank account details receive immediately IRS",
  "Confirm password link expires hour Act fast immediately mandatory",
  "Netflix subscription failed Update payment details immediately suspended",
  "Inheritance claim beneficiary Provide details claim million dollars",
  "Account locked unusual Verify email unlock mandatory immediately",
  "Login credentials expire Reset password immediately mandatory urgent",
  "Security breach Validate identity within 24 hours mandatory",
  "Social security number flagged Confirm SSN resolve suspended",
  "Won lottery prize Send banking details claim winnings immediately",
  "Credit card suspicious transactions Verify card number immediately fraud",
  "Urgent delivery Confirm home address date birth receive parcel",
  "Unauthorized transfer attempted Authorize deny transaction immediately",
  "Google account deleted Re-confirm password keep access immediately",
  "Free iPad confirm credit card shipping handling limited time",
  "Billing subscription canceled Update payment method immediately penalty",
  "Verify identity Provide full name address date birth mandatory",
  "PayPal unusual Confirm identity link immediately suspended fraud",
  "Account verification pending Log immediately complete mandatory",
  "Recover account Someone tried credentials Act immediately urgent",
  "Spotify premium failed Update card CVV continue immediately",
  "Bonus reward claim offer expires today urgent limited mandatory",
  "Account password reset without permission Verify control mandatory",
  "Verify credentials entering username password phishing mandatory",
  "Wire transfer ten thousand Cancel immediately clicking fraud mandatory",
  "Email data breach Secure updating credentials immediately urgent",
  "Unusual login Russia Confirm account locked immediately suspended",
  "Domain expire Renew billing information immediately mandatory penalty",
  "Bank fraudulent transactions Confirm account number pin immediately",
  "Millionth visitor Claim gift card immediately prize reward",
  "McAfee license virus expired Click renew immediately mandatory",
  "IRS tax return verification Provide SSN bank routing number",
  "Someone tried access account Reset password mandatory immediately",
  "DHL parcel pending Pay customs fee credit card mandatory fraud",
  "Suspended violated terms Confirm identity appeal mandatory",
  "Validate account urgently Critical security update credentials mandatory",
  "Winner notification Provide details collect prize money immediately",
  "Secure PayPal Unusual transaction Verify identity right immediately",
  "Windows license expired Update payment information mandatory",
  "eBay account flagged Provide billing continue selling mandatory",
  "Netflix payment suspended 12 hours immediately mandatory",
  "Apple ID bought iPhone China Verify identity immediately fraud",
  "WhatsApp risk Provide verification code secure immediately",
  "iPhone giveaway selected Enter card delivery immediately mandatory",
  "Bank restricted Click enter credentials restore mandatory",
  "Unauthorized login detected secure immediately mandatory suspended",
  "Account compromised suspended credentials phishing mandatory click",
  "Urgent warning expire penalty fraud stolen unauthorized mandatory",
  "Lottery inheritance prize million claim mandatory banking",
  "Suspended fraud unauthorized click immediately mandatory credentials",
];

// 100 LEGIT emails — increased from 60, now covers transactional + security notifications
const LEGIT_EMAILS = [
  // Professional / team emails
  "Hi team please find attached quarterly report Q1 2025 Let me know questions",
  "Meeting reminder Standup call tomorrow 10am Please join usual video",
  "Hi Sarah just following up project proposal discussed last week Any updates",
  "Newsletter new features live Check new version 3.0 platform",
  "Great news team performed exceptionally well quarter highlights",
  "Weekly digest top articles week technology science",
  "Hi John can review attached document share feedback Friday",
  "Thank you contacting support ticket created respond shortly",
  "Team outing Friday RSVP Wednesday Fun activities planned everyone",
  "GitHub pull request approved merged into main branch",
  "Reminder annual performance review scheduled next Tuesday",
  "Hi there Just wanted share interesting article across Hope enjoy",
  "New product catalog now available Browse latest collection online",
  "Congratulations completing training course certificate attached",
  "Board meeting notes Thursday attached Please review next session",
  "feedback matters Please take 2 minutes complete customer satisfaction survey",
  "Happy birthday Wishing wonderful year ahead Best wishes whole team",
  "New comment blog post Great article very informative well written",
  "PTO request submitted approved manager Enjoy vacation",
  "HR update New workplace wellness initiatives starting next month Details",
  "IT support ticket resolved Please let know need further help",
  "project deadline moved April 15 Please update work schedules accordingly",
  "Good morning weather forecast week Expect sunshine most days",
  "Lunch meeting confirmed Tuesday 12:30 downtown café Looking forward",
  "Team please ensure timesheets submitted end day Friday Thank",
  "research paper co-authored accepted publication Congratulations",
  "Hi reaching out potential collaborator loved work project",
  "library books due 3 days Please return renew online",
  "Thanks attending webinar recording link slide deck",
  "Please review draft contract send back comments end week",
  "Friendly reminder dental appointment Thursday 9am Call reschedule",
  "pleased inform loan application approved",
  "Join virtual happy hour Friday 5pm Hope see there",
  "new office supplies order arrived Please collect items reception",
  "Code review request Please review PR 234 sprint ends Friday",
  "Company announcements New CEO appointed Q2 goals published team updates",
  "Zoom recording ready View share meeting recording using",
  "All-hands meeting notes action items morning session attached",
  "Thanks referral friend signed bonus applied",
  "agenda next week strategy session Please come prepared discuss",
  "conference schedule finalized talk confirmed Day 2 Slot 3",
  "Hi Mark just checking budget proposal ETA revised numbers",
  "Customer success story Read Acme Corp saved 30 percent platform",
  "Deployment complete Version 2.4.1 now live production Changelog attached",
  "Updated privacy policy notification No action required keeping informed",
  "Welcome community tips get started platform",
  "End year review Summary accomplishments goals upcoming year",
  "Reminder fire drill scheduled 2pm tomorrow Please evacuate protocol",
  "AWS bill February 142.30 View detailed usage billing console",
  "salary deposited payslip March available HR portal",
  // Transactional emails (often trigger false positives)
  "Your order has been shipped Tracking number XYZ123 delivery expected",
  "Thank you purchase Order 12345 shipped Tracking information enclosed",
  "Your monthly statement ready Log view balance at convenience",
  "Your subscription renewed next billing date April",
  "Invoice paid successfully Thank prompt payment",
  "appointment confirmed March 20 2pm See clinic",
  "We hope enjoyed recent stay hotel Please share feedback",
  "Your flight booking confirmed Check-in opens 24 hours before departure",
  "Your package delivered front door Thank shopping",
  "Your annual subscription Adobe Creative Cloud renewed same rate",
  "tax documents 2024 ready download portal",
  "We pleased inform you selected scholarship program",
  // Security-related LEGIT emails (hardest for NB to classify correctly)
  "We noticed new login your account from device If this was you no action needed",
  "Someone new signed into account If this was you can ignore",
  "Two-factor authentication code is 847291 Do not share anyone",
  "successfully changed password If you did not make change contact support",
  "New device added account If recognize device no action needed",
  "Your password reset successfully If you did not request this contact support team",
  "Verification code 339821 expires 10 minutes valid one time",
  "Our records show password not changed 90 days recommend updating when convenient",
  "successfully logged from Chrome Windows 10 If this was you",
  "New sign-in detected account Review activity if anything looks unfamiliar",
  "recovery email added account If not let support know right away",
  "Two-step verification enabled account great step security",
  // Email with common trigger words used legitimately
  "Please update your personal details in the HR system at your earliest convenience",
  "We are conducting a security awareness training session next Friday all staff",
  "IT team will perform scheduled maintenance system on Sunday no action required",
  "Your staff ID card expired please visit HR to collect renewed card",
  "Please confirm your availability for the product demo scheduled Thursday",
  "The team needs your approval on the attached budget before end of quarter",
  "Please review and sign the attached NDA before the client meeting",
  "Your credit card ending 4242 has been added to your profile successfully",
  "Bank statement for March is ready to download from online banking portal",
  "Payroll processing complete salaries credited to accounts by Friday",
  "Important policy update regarding remote work guidelines see attached document",
  "Your identity verification is complete account fully activated enjoy",
  "We have received your complaint and are investigating the matter promptly",
  "Your refund of 45.00 has been processed allow 3-5 business days to reflect",
  "Direct deposit information updated payroll department successfully",
  "Your resume has been received and is under review by our HR team",
  "System maintenance scheduled this weekend no data loss expected",
  "Background check successfully completed welcome aboard looking forward",
  "Your benefits enrollment confirmed Summary attached for records",
  // ── FORMAL / PROFESSIONAL emails (cover letters, applications, inquiries) ──
  "writing express interest cybersecurity internship opportunity organization eager gain practical industry experience",
  "pursuing degree bachelor computer science third year developing knowledge networking fundamentals analysis",
  "graduate student writing apply software engineering position enclosed resume portfolio consideration interview",
  "faculty member writing recommendation outstanding student academic excellent research analytical skills",
  "writing inform shortlisted interview position schedule convenient time discuss further details",
  "pleased announce selected scholarship program academic merit enclosed acceptance letter congratulations",
  "submitting final year project report supervisor review feedback dissertation academic requirements",
  "writing express gratitude mentorship guidance throughout academic journey invaluable professional growth",
  "job application software developer position five years relevant experience attached resume references",
  "following recent conversation recruitment fair attached resume cover letter consideration entry level role",
  "undergraduate thesis proposal submitted committee review feedback methodology research objectives scope",
  "seminar workshop registration confirmed scheduled venue details agenda speakers enclosed forward attending",
  "academic transcript attached scholarship application committee review eligibility requirements criteria",
  "writing request meeting professor discuss project progress research direction academic supervisor",
  "pleased offer admission masters program starting September enclosed enrollment details registration",
  "internship completion certificate attached successful completion program supervisor signed endorsed",
  "college event cultural technical fest invitation participation registration details venue schedule",
  "reference letter enclosed requested professional academic character qualifications achievements highlighted",
  "writing proposal collaboration research joint publication institutions mutual benefit academic community",
  "notification exam results published portal academic transcript issued upon request official records",
  "club society membership renewal annual subscription activities schedule upcoming events calendar",
  "writing thank interview opportunity thoroughly enjoyed discussion team culture compelling mission",
  "placement coordinator writing regarding campus recruitment drive companies visiting schedule registration",
  "academic counselor appointment scheduled guidance course selection career path planning discussion",
  "writing follow application submitted weeks ago status update consideration timeline recruitment process",
];

/* ─────────────────────── NAIVE BAYES with FIXES ─────────────────────── */

class NaiveBayesClassifier {
  constructor() {
    this.phishingWordFreq  = {};
    this.legitWordFreq     = {};
    this.phishingWordTotal = 0;
    this.legitWordTotal    = 0;
    this.phishingDocs      = 0;
    this.legitDocs         = 0;
    this.vocab             = new Set();
    this.smoothing         = 1;
    this._trained          = false;
  }

  /**
   * FIX #1 + #2: Tokenize with stopword removal + per-doc deduplication.
   * Using a Set per document prevents repeated words from dominating.
   */
  tokenize(text, deduplicate = false) {
    const tokens = text
      .toLowerCase()
      .replace(/[^a-z\s]/g, ' ')
      .split(/\s+/)
      .filter(w => w.length > 2 && w.length < 25 && !STOPWORDS.has(w));

    return deduplicate ? [...new Set(tokens)] : tokens;
  }

  /** Train the model */
  train(phishingSamples, legitSamples) {
    this.phishingDocs = phishingSamples.length;
    this.legitDocs    = legitSamples.length;

    // FIX #2: use deduplicate=true during training
    phishingSamples.forEach(text => {
      this.tokenize(text, true).forEach(token => {
        this.phishingWordFreq[token] = (this.phishingWordFreq[token] || 0) + 1;
        this.phishingWordTotal++;
        this.vocab.add(token);
      });
    });

    legitSamples.forEach(text => {
      this.tokenize(text, true).forEach(token => {
        this.legitWordFreq[token] = (this.legitWordFreq[token] || 0) + 1;
        this.legitWordTotal++;
        this.vocab.add(token);
      });
    });

    this._trained = true;
    console.log(`✅ Naive Bayes v3.1 trained: ${this.phishingDocs} phishing, ${this.legitDocs} legit | vocab=${this.vocab.size}`);
  }

  /**
   * Predict class for a text.
   * FIX #3: Raised thresholds and FIX #5: Adjusted prior to favor legit class.
   */
  predict(text) {
    if (!this._trained) throw new Error('Model not trained');

    const V      = this.vocab.size;
    // FIX #2: also deduplicate at inference so repeated words don't dominate
    const tokens = this.tokenize(text, true);

    if (tokens.length < 3) {
      // Very short text → default to safe, low confidence
      return { label: 'Safe', score: 10, confidence: 0.1, topTokens: [], rawProbability: 0.1 };
    }

    // FIX #5: Prior slightly biased toward legit to reduce false positives
    // 0.45 phishing prior vs 0.55 legit prior (instead of 50/50)
    let logPhishing = Math.log(0.45);
    let logLegit    = Math.log(0.55);

    const tokenScores = {};

    tokens.forEach(token => {
      const pPhishing = (this.phishingWordFreq[token] || 0) + this.smoothing;
      const pLegit    = (this.legitWordFreq[token]    || 0) + this.smoothing;
      const denomP    = this.phishingWordTotal + this.smoothing * V;
      const denomL    = this.legitWordTotal    + this.smoothing * V;

      const logP = Math.log(pPhishing / denomP);
      const logL = Math.log(pLegit    / denomL);

      logPhishing += logP;
      logLegit    += logL;

      const diff = logP - logL;
      if (Math.abs(diff) > 0.5 && this.vocab.has(token)) {
        tokenScores[token] = diff;
      }
    });

    // Softmax to probability
    const maxLog    = Math.max(logPhishing, logLegit);
    const expP      = Math.exp(logPhishing - maxLog);
    const expL      = Math.exp(logLegit    - maxLog);
    const probPhish = expP / (expP + expL);

    const topTokens = Object.entries(tokenScores)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([word, diff]) => ({ word, contribution: Math.round(diff * 100) / 100 }));

    const score = Math.round(probPhish * 100);

    // FIX #3: Raised thresholds
    let label = 'Safe';
    if      (score >= 72) label = 'Phishing';
    else if (score >= 48) label = 'Suspicious';

    return {
      label,
      score,
      confidence: Math.abs(probPhish - 0.5) * 2,
      topTokens,
      rawProbability: probPhish
    };
  }
}

/* ─────────────────────── RANDOM-FOREST URL CLASSIFIER ─────────────────────── */

const URL_TREES = [
  // Tree 1: Domain structure
  url => {
    let score = 0;
    try {
      const u = new URL(url);
      const subdomainCount = u.hostname.split('.').length - 2;
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname)) score += 85;
      if (subdomainCount >= 4) score += 70;
      else if (subdomainCount === 3) score += 40;
      if (u.hostname.length > 40) score += 30;
      if (u.protocol !== 'https:') score += 25;
    } catch { score = 0; }
    return Math.min(score, 100);
  },

  // Tree 2: URL length & special chars
  url => {
    let score = 0;
    if (url.length > 200) score += 60;
    else if (url.length > 100) score += 30;
    if ((url.match(/@/g)  || []).length > 0)  score += 50;
    if ((url.match(/-/g)  || []).length > 5)  score += 25;
    if ((url.match(/=/g)  || []).length > 5)  score += 20;
    if ((url.match(/%/g)  || []).length > 3)  score += 30;
    if ((url.match(/%[0-9a-fA-F]{2}/g) || []).length > 3) score += 35;
    return Math.min(score, 100);
  },

  // Tree 3: Brand impersonation & TLD
  url => {
    let score = 0;
    const brands = ['paypal','amazon','microsoft','google','apple','facebook',
                    'netflix','spotify','ebay','instagram','twitter','linkedin',
                    'bank','secure','login'];
    try {
      const u    = new URL(url);
      const host = u.hostname.toLowerCase();
      const legitimateRoot = brands.slice(0, 12).some(b =>
        host === `${b}.com` || host === `www.${b}.com`
      );
      if (brands.some(b => host.includes(b)) && !legitimateRoot) score += 75;
      const suspPath = ['login','verify','confirm','secure','update','billing','password'];
      if (suspPath.some(p => u.pathname.toLowerCase().includes(p))) score += 35;
      const badTlds = ['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.click','.info','.biz'];
      if (badTlds.some(t => host.endsWith(t))) score += 40;
    } catch { score = 10; }
    return Math.min(score, 100);
  },

  // Tree 4: Shorteners & redirects
  url => {
    let score = 0;
    const shorteners = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly',
                        'short.link','tiny.cc','is.gd','buff.ly','cutt.ly'];
    if (shorteners.some(s => url.toLowerCase().includes(s))) score += 70;
    const redirectParams = ['redirect=','url=','goto=','link=','out=','redir='];
    if (redirectParams.some(p => url.toLowerCase().includes(p))) score += 45;
    if (url.includes('%25')) score += 50;
    return Math.min(score, 100);
  },

  // Tree 5: Punycode & path depth
  url => {
    let score = 0;
    if (url.includes('xn--')) score += 65;
    try {
      const u     = new URL(url);
      const depth = u.pathname.split('/').filter(Boolean).length;
      if (depth > 6) score += 40;
      else if (depth > 4) score += 20;
      const paramCount = Array.from(u.searchParams.keys()).length;
      if (paramCount > 8) score += 35;
      else if (paramCount > 4) score += 15;
      if (u.port && !['80','443','8080','8443'].includes(u.port)) score += 40;
    } catch { score = 0; }
    return Math.min(score, 100);
  }
];

const TREE_WEIGHTS = [0.30, 0.20, 0.25, 0.15, 0.10];

class RandomForestURLClassifier {
  predict(url) {
    const votes       = URL_TREES.map((tree, i) => ({ tree: i+1, vote: tree(url), weight: TREE_WEIGHTS[i] }));
    const weightedSum = votes.reduce((sum, v) => sum + v.vote * v.weight, 0);
    const score       = Math.round(Math.min(weightedSum, 100));

    let label = 'Safe';
    if (score >= 60) label = 'Malicious';
    else if (score >= 30) label = 'Suspicious';

    const mean       = votes.reduce((s, v) => s + v.vote, 0) / votes.length;
    const variance   = votes.reduce((s, v) => s + Math.pow(v.vote - mean, 2), 0) / votes.length;
    const confidence = Math.max(0, 1 - (Math.sqrt(variance) / 50));
    const riskFactors = this._extractRiskFactors(url);

    return { label, score, confidence: Math.round(confidence * 100) / 100, treeVotes: votes, riskFactors };
  }

  _extractRiskFactors(url) {
    const factors = [];
    try {
      const u = new URL(url);

      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname))
        factors.push({ factor: 'IP address used as domain', severity: 'critical', weight: 85 });

      const sc = u.hostname.split('.').length - 2;
      if (sc >= 3)
        factors.push({ factor: `Excessive subdomains (${sc})`, severity: 'high', weight: 60 });

      if (u.protocol !== 'https:')
        factors.push({ factor: 'No HTTPS encryption', severity: 'medium', weight: 25 });

      if (url.includes('xn--'))
        factors.push({ factor: 'Punycode / IDN homograph attack', severity: 'critical', weight: 80 });

      const brands = ['paypal','amazon','microsoft','google','apple','facebook','netflix'];
      const imp = brands.find(b =>
        u.hostname.includes(b) &&
        u.hostname !== `${b}.com` &&
        u.hostname !== `www.${b}.com`
      );
      if (imp)
        factors.push({ factor: `Brand impersonation: "${imp}"`, severity: 'critical', weight: 75 });

      if (['bit.ly','tinyurl','t.co','goo.gl'].some(s => url.includes(s)))
        factors.push({ factor: 'URL shortener hides destination', severity: 'high', weight: 70 });

      if (url.length > 200)
        factors.push({ factor: `Unusually long URL (${url.length} chars)`, severity: 'medium', weight: 40 });

      if ((url.match(/@/g)||[]).length > 0)
        factors.push({ factor: 'URL contains "@" — possible redirect trick', severity: 'high', weight: 50 });

      const badTlds = ['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.click'];
      if (badTlds.some(t => u.hostname.endsWith(t)))
        factors.push({ factor: `High-risk TLD: ${u.hostname.split('.').slice(-1)[0]}`, severity: 'high', weight: 40 });

      if ((url.match(/%[0-9a-fA-F]{2}/g) || []).length > 3)
        factors.push({ factor: 'Heavy URL encoding / obfuscation', severity: 'medium', weight: 35 });

      if (['redirect=','url=','goto=','link='].some(p => url.toLowerCase().includes(p)))
        factors.push({ factor: 'Open redirect parameter detected', severity: 'high', weight: 45 });

    } catch {
      factors.push({ factor: 'Malformed URL structure', severity: 'medium', weight: 30 });
    }

    return factors.sort((a, b) => b.weight - a.weight);
  }
}

/* ─────────────────────── SINGLETON & STARTUP ─────────────────────── */

const emailModel = new NaiveBayesClassifier();
const urlModel   = new RandomForestURLClassifier();

let _trained = false;
function ensureTrained() {
  if (_trained) return;
  emailModel.train(PHISHING_EMAILS, LEGIT_EMAILS);
  _trained = true;
}

/* ─────────────────────────────────────────────────────────────
 *  FORMAL EMAIL CONTEXT DETECTOR
 *  Scores how "professional/polite" an email is on 0-100.
 *  High formal scores dampen the NB threat score to fix FP
 *  on cover letters, academic emails, internship requests etc.
 * ─────────────────────────────────────────────────────────────*/
function formalEmailScore(text) {
  const lower = text.toLowerCase();
  let score = 0;

  // Polite salutations (strong signal)
  if (/\b(dear sir|dear madam|dear sir\s*\/\s*madam|respected sir|to whom it may concern)\b/i.test(text)) score += 30;
  else if (/\b(hi |hello |good morning|good afternoon|good evening)\b/i.test(text)) score += 15;

  // Self-introduction patterns (almost never in phishing)
  if (/\bmy name is\b/i.test(text))                          score += 25;
  if (/\bi am (currently |a )?(pursuing|studying|enrolled)\b/i.test(text)) score += 25;
  if (/\b(3rd|third|second|final|first)\s+year\b/i.test(text)) score += 20;
  if (/\b(be|btech|bsc|msc|mtech|bachelor|master|phd|graduate|undergraduate)\b/i.test(text)) score += 20;
  if (/\b(computer science|information technology|engineering|cse|ece|cybersecurity)\b/i.test(text)) score += 15;

  // Professional intent (never phishing)
  if (/\b(internship|job application|apply for|applying for)\b/i.test(text)) score += 25;
  if (/\bcover letter\b/i.test(text))                        score += 20;
  if (/\b(attached (is|are)? (my )?resume|resume attached|cv attached)\b/i.test(text)) score += 25;
  if (/\b(look forward to hearing|look forward to your response|await your response)\b/i.test(text)) score += 20;
  if (/\b(gain (practical|industry|professional) experience)\b/i.test(text)) score += 20;

  // Polite closings (very strong signal)
  if (/\b(best regards|warm regards|kind regards|sincerely|yours (truly|faithfully|sincerely)|respectfully)\b/i.test(text)) score += 25;
  if (/\bthank you for (your time|considering|your consideration)\b/i.test(text)) score += 20;

  // Academic / professional context words
  if (/\b(professor|lecturer|manager|hr|recruiter|hiring manager)\b/i.test(text)) score += 15;
  if (/\b(skills|expertise|proficiency|qualifications|achievements)\b/i.test(text)) score += 10;
  if (/\b(portfolio|linkedin|github|reference)\b/i.test(text)) score += 10;

  return Math.min(score, 100);
}

/* ─────────────────────── PUBLIC API ─────────────────────── */

function classifyEmail(text) {
  ensureTrained();

  // ── Step 1: Check for formal/professional email markers ──────────
  const formalScore = formalEmailScore(text);
  let nbResult      = emailModel.predict(text);

  // ── Step 2: If strong formal signals detected, dampen NB score ──
  //   Formula: if formalScore ≥ 50, apply a dampening that pushes
  //   the NB score toward 0. The stronger the formal signal, the
  //   greater the dampening. This is a soft override, not a hard one.
  if (formalScore >= 50) {
    const dampFactor  = (formalScore - 50) / 50;  // 0.0–1.0
    const dampedScore = Math.round(nbResult.score * (1 - dampFactor * 0.85));
    // Rebuild a modified result with the dampened score
    let newLabel = 'Safe';
    if (dampedScore >= 72) newLabel = 'Phishing';
    else if (dampedScore >= 48) newLabel = 'Suspicious';
    nbResult = { ...nbResult, score: dampedScore, label: newLabel };
  }

  const phishTokens = nbResult.topTokens.filter(t => t.contribution > 0).map(t => t.word);
  const safeTokens  = nbResult.topTokens.filter(t => t.contribution < 0).map(t => t.word);
  const confLabel   = nbResult.confidence > 0.75 ? 'High' : nbResult.confidence > 0.45 ? 'Medium' : 'Low';

  return {
    engine: 'Naive Bayes ML v3.2',
    label:       nbResult.label,
    threatScore: nbResult.score,
    confidence:  { level: confLabel, value: Math.round(nbResult.confidence * 100) },
    features: {
      suspiciousKeywords: phishTokens.slice(0, 6),
      phishingPhrases:    phishTokens.slice(0, 3),
      safeIndicators:     safeTokens.slice(0, 4),
    },
    explanation: {
      summary:           _emailSummary(nbResult),
      topPhishingTokens: phishTokens,
      topSafeTokens:     safeTokens,
      recommendation:    _emailRecommendation(nbResult.label),
      formalScore,
      riskFactors: phishTokens.slice(0, 8).map(word => ({
        title:       word,
        description: `"${word}" strongly correlates with phishing in training data`,
        severity:    nbResult.score > 72 ? 'high' : 'medium'
      }))
    }
  };
}

function classifyURL(url) {
  const result    = urlModel.predict(url);
  const confLabel = result.confidence > 0.75 ? 'High' : result.confidence > 0.45 ? 'Medium' : 'Low';

  return {
    engine: 'Random Forest ML v3.1',
    label:       result.label,
    threatScore: result.score,
    confidence:  { level: confLabel, value: Math.round(result.confidence * 100) },
    features: {
      suspiciousKeywords: result.riskFactors.map(r => r.factor),
      maliciousPatterns:  result.riskFactors.filter(r => r.severity === 'critical').map(r => r.factor),
    },
    explanation: {
      summary:           _urlSummary(result),
      treeVotes:         result.treeVotes,
      recommendation:    _urlRecommendation(result.label),
      riskFactors: result.riskFactors.map(r => ({
        title:       r.factor,
        description: `Severity: ${r.severity} — detected by Random Forest ensemble`,
        severity:    r.severity
      }))
    }
  };
}

function _emailSummary({ label, score }) {
  if (label === 'Phishing')   return `🚨 ML classified this email as PHISHING (score: ${score}/100). High probability of malicious intent.`;
  if (label === 'Suspicious') return `⚠️ ML flagged this email as SUSPICIOUS (score: ${score}/100). Treat with caution.`;
  return `✅ ML classified this email as SAFE (score: ${score}/100). Appears to be legitimate.`;
}

function _urlSummary({ label, score }) {
  if (label === 'Malicious')  return `🚨 Random Forest classified this URL as MALICIOUS (score: ${score}/100). Do not visit.`;
  if (label === 'Suspicious') return `⚠️ Random Forest flagged this URL as SUSPICIOUS (score: ${score}/100). Proceed with caution.`;
  return `✅ Random Forest classified this URL as SAFE (score: ${score}/100). No major threats detected.`;
}

function _emailRecommendation(label) {
  if (label === 'Phishing')   return 'Do not click links or provide personal information. Report as phishing and delete.';
  if (label === 'Suspicious') return 'Be cautious. Verify the sender independently before clicking links or attachments.';
  return 'Email appears legitimate. Stay vigilant about unexpected requests.';
}

function _urlRecommendation(label) {
  if (label === 'Malicious')  return 'Do not visit this URL. Strong characteristics of a malicious or phishing site.';
  if (label === 'Suspicious') return 'Approach with caution. Verify the website before entering any personal data.';
  return 'URL appears safe. Always verify the domain before sharing sensitive information.';
}

module.exports = { classifyEmail, classifyURL, ensureTrained };
