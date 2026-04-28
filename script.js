const authForm = document.getElementById("authForm");
const policyForm = document.getElementById("policyForm");
const resultCard = document.getElementById("resultCard");
const auditLog = document.getElementById("auditLog");
const accessStatus = document.getElementById("accessStatus");
const securityScore = document.getElementById("securityScore");
const protectedAccounts = document.getElementById("protectedAccounts");
const minLength = document.getElementById("minLength");
const minLengthValue = document.getElementById("minLengthValue");
const policySummary = document.getElementById("policySummary");
const lockoutThreshold = document.getElementById("lockoutThreshold");
const clearLog = document.getElementById("clearLog");

let accountCount = 1;

function nowStamp() {
  return new Date().toLocaleString([], {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  });
}

function evaluatePassword(password, minimum, requireSpecial, requireNumbers, requireUppercase) {
  const hasSpecial = /[^A-Za-z0-9]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasUppercase = /[A-Z]/.test(password);
  const hasLength = password.length >= minimum;

  const checks = [
    hasLength,
    !requireSpecial || hasSpecial,
    !requireNumbers || hasNumber,
    !requireUppercase || hasUppercase
  ];

  const passed = checks.filter(Boolean).length;
  return {
    isValid: checks.every(Boolean),
    passed,
    total: checks.length
  };
}

function appendLog(message, risk) {
  const item = document.createElement("li");
  item.innerHTML = `
    <span class="log-time">${nowStamp()}</span>
    <strong class="log-message ${risk}">${message}</strong>
  `;
  auditLog.prepend(item);
}

function updatePolicySummary() {
  const min = Number(minLength.value);
  const requireSpecial = document.getElementById("requireSpecial").checked;
  const requireNumbers = document.getElementById("requireNumbers").checked;
  const requireUppercase = document.getElementById("requireUppercase").checked;
  const geoFence = document.getElementById("geoFence").checked;
  const rotation = document.getElementById("rotationPeriod").value;

  minLengthValue.textContent = `${min} characters`;
  lockoutThreshold.textContent = min >= 14 ? "3 attempts" : "5 attempts";

  let score = 56;
  score += min >= 12 ? 10 : 0;
  score += requireSpecial ? 8 : 0;
  score += requireNumbers ? 8 : 0;
  score += requireUppercase ? 8 : 0;
  score += geoFence ? 10 : 0;
  score += rotation === "30" ? 6 : rotation === "60" ? 4 : rotation === "90" ? 2 : 0;

  securityScore.textContent = `${Math.min(score, 100)}%`;
  policySummary.innerHTML = `
    <h3>Policy Snapshot</h3>
    <p>
      Passwords must be at least <strong>${min} characters</strong> and rotate every
      <strong>${rotation} days</strong>. Special characters are <strong>${requireSpecial ? "required" : "optional"}</strong>,
      numbers are <strong>${requireNumbers ? "required" : "optional"}</strong>, uppercase letters are
      <strong>${requireUppercase ? "required" : "optional"}</strong>, and geolocation anomaly blocking is
      <strong>${geoFence ? "enabled" : "disabled"}</strong>.
    </p>
  `;
}

function setResult(title, description, tone) {
  resultCard.innerHTML = `<h3 class="${tone}">${title}</h3><p>${description}</p>`;
}

function handleAuthentication(event) {
  event.preventDefault();

  const formData = new FormData(authForm);
  const username = formData.get("username").trim();
  const password = formData.get("password");
  const mfaMethod = formData.get("mfaMethod");
  const otp = formData.get("otp").trim();
  const deviceTrust = formData.get("deviceTrust");
  const location = formData.get("location").trim();
  const privilegedAccess = formData.get("privilegedAccess") === "on";
  const rememberDevice = formData.get("rememberDevice") === "on";

  const min = Number(minLength.value);
  const requireSpecial = document.getElementById("requireSpecial").checked;
  const requireNumbers = document.getElementById("requireNumbers").checked;
  const requireUppercase = document.getElementById("requireUppercase").checked;
  const geoFence = document.getElementById("geoFence").checked;

  const passwordResult = evaluatePassword(
    password,
    min,
    requireSpecial,
    requireNumbers,
    requireUppercase
  );

  const otpValid = /^\d{6}$/.test(otp);
  const suspiciousLocation = geoFence && !/india|office|hq|campus/i.test(location);
  const restrictedDevice = deviceTrust !== "Trusted";

  if (!passwordResult.isValid) {
    accessStatus.textContent = "Blocked";
    accessStatus.style.color = "var(--red)";
    setResult(
      "Authentication blocked",
      `Password policy validation failed for ${username || "the supplied account"}. ${passwordResult.passed}/${passwordResult.total} password checks passed.`,
      "risk-high"
    );
    appendLog(`Blocked sign-in for ${username || "unknown user"} because the password did not meet policy requirements.`, "risk-high");
    return;
  }

  if (!otpValid) {
    accessStatus.textContent = "Step-Up Required";
    accessStatus.style.color = "var(--amber)";
    setResult(
      "Second factor rejected",
      `The ${mfaMethod} challenge could not be verified. A valid 6-digit code is required before access can proceed.`,
      "risk-medium"
    );
    appendLog(`Rejected MFA challenge for ${username || "unknown user"} due to invalid OTP input.`, "risk-medium");
    return;
  }

  if (suspiciousLocation || restrictedDevice || privilegedAccess) {
    accessStatus.textContent = "Conditional Access";
    accessStatus.style.color = "var(--amber)";
    setResult(
      "Conditional approval issued",
      `${username} passed primary checks, but the session was flagged for ${suspiciousLocation ? "location anomaly" : restrictedDevice ? "device trust review" : "privileged access review"}. Additional verification should be enforced.`,
      "risk-medium"
    );
    appendLog(`Conditional access granted to ${username} using ${mfaMethod} from ${location}.`, "risk-medium");
  } else {
    accessStatus.textContent = "Approved";
    accessStatus.style.color = "var(--teal)";
    setResult(
      "Authentication successful",
      `${username} authenticated with ${mfaMethod}. Device state is ${deviceTrust.toLowerCase()} and trusted session memory is ${rememberDevice ? "enabled" : "disabled"}.`,
      "risk-low"
    );
    appendLog(`Successful sign-in for ${username} from ${location} using ${mfaMethod}.`, "risk-low");
  }

  accountCount += 1;
  protectedAccounts.textContent = String(accountCount).padStart(2, "0");
}

minLength.addEventListener("input", updatePolicySummary);
policyForm.addEventListener("change", updatePolicySummary);
authForm.addEventListener("submit", handleAuthentication);
clearLog.addEventListener("click", () => {
  auditLog.innerHTML = "";
  appendLog("Audit trail cleared by administrator.", "risk-medium");
});

updatePolicySummary();
appendLog("Framework initialized. Monitoring sign-in requests and enforcing policy baseline.", "risk-low");
