// This tiny client demonstrates the JSON API; the server remains authoritative.
let accessToken = "";

const result = document.querySelector("#result");
const emailInput = document.querySelector("#email");
const passwordInput = document.querySelector("#password");

async function callApi(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...options.headers };
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  const response = await fetch(path, { ...options, headers });
  const data = await response.json();
  result.textContent = `${response.status} ${response.statusText}\n${JSON.stringify(data, null, 2)}`;
  return { response, data };
}

document.querySelector("#register").addEventListener("click", () => {
  callApi("/api/auth/register", {
    method: "POST",
    body: JSON.stringify({ email: emailInput.value, password: passwordInput.value }),
  });
});

document.querySelector("#login").addEventListener("click", async () => {
  const { response, data } = await callApi("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ email: emailInput.value, password: passwordInput.value }),
  });
  if (response.ok) accessToken = data.access_token;
});

document.querySelector("#profile").addEventListener("click", () => {
  callApi("/api/me");
});

