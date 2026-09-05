// Chiffrement simple avec Web Crypto API
const CRYPTO_KEY = 'SafeBrowseGov2024!';

async function encryptData(data) {
  try {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(CRYPTO_KEY.padEnd(32, '0').slice(0, 32));
    const key = await crypto.subtle.importKey('raw', keyData, {name: 'AES-GCM'}, false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({name: 'AES-GCM', iv: iv}, key, encoder.encode(data));
    
    return btoa(String.fromCharCode(...iv) + String.fromCharCode(...new Uint8Array(encrypted)));
  } catch (e) {
    console.error('Erreur chiffrement:', e);
    return btoa(data); // Fallback
  }
}

async function decryptData(encryptedData) {
  try {
    const decoder = new TextDecoder();
    const data = atob(encryptedData);
    const iv = new Uint8Array(Array.from(data.slice(0, 12)).map(c => c.charCodeAt(0)));
    const encrypted = new Uint8Array(Array.from(data.slice(12)).map(c => c.charCodeAt(0)));
    
    const encoder = new TextEncoder();
    const keyData = encoder.encode(CRYPTO_KEY.padEnd(32, '0').slice(0, 32));
    const key = await crypto.subtle.importKey('raw', keyData, {name: 'AES-GCM'}, false, ['decrypt']);
    const decrypted = await crypto.subtle.decrypt({name: 'AES-GCM', iv: iv}, key, encrypted);
    
    return decoder.decode(decrypted);
  } catch (e) {
    console.error('Erreur déchiffrement:', e);
    return atob(encryptedData); // Fallback
  }
}