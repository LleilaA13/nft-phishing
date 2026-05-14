# NFT Metadata Error Analysis

**Analysis Date:** May 14, 2026  
**Data Source:** `nft_metadata_robust.csv`  
**Total Errors Found:** 3,576  
**Unique Error Types:** 37

---

## Error Summary by Category

### 1. **Metadata Fetch Failures** (1,521 errors - 42.6%)
```
Error: metadata_fetch_failed
```
**Description:** Unable to fetch or retrieve metadata from the provided URI. This is the most common error type, indicating that the metadata endpoint is unreachable, returns no data, or times out.

---

### 2. **Execution Reverted Errors** (935 errors - 26.2%)
```
Error: ('execution reverted: 0x', '0x')
```
**Description:** Generic execution revert without detailed error information. Typically occurs when calling smart contract functions fails with empty error data.

---

### 3. **Empty URI** (356 errors - 10.0%)
```
Error: empty_uri
```
**Description:** The NFT's tokenURI is empty or null. The contract doesn't provide a valid metadata URI.

---

### 4. **Invalid Token ID Errors** (206 errors - 5.8%)
```
Error: ('execution reverted: ERC721: invalid token ID: 0x08c379a00000...'
```
**Description:** The token ID is invalid or does not exist in the contract. Common for revoked or burned tokens.

---

### 5. **Generic Revert Code** (158 errors - 4.4%)
```
Error: ('0x7e2732890000000000000000000000000000000000000000000000000000000000000002', '0x7e273289...')
```
**Description:** Execution reverted with specific error code `0x7e278289`. Actual error message is encoded in the revert data.

---

### 6. **No Tokens Minted** (158 errors - 4.4%)
```
Error: no_tokens_minted
```
**Description:** The contract exists but has no tokens minted. Usually indicates a newly created or abandoned contract.

---

### 7. **Unsupported Token URI** (154 errors - 4.3%)
```
Error: unsupported_token_uri
```
**Description:** The token URI format is not supported or cannot be processed (e.g., unusual schemes or formats).

---

### 8. **ERC721Metadata URI Query Failure** (18 errors - 0.5%)
```
Error: ('execution reverted: ERC721Metadata: URI query for nonexistent token: 0x08c379a0...'
```
**Description:** Standard ERC-721 metadata query failure for a token that doesn't exist on-chain.

---

### 9. **URI Query for Nonexistent Token** (10 errors - 0.3%)
```
Error: ('execution reverted: URI query for nonexistent token: 0x08c379a0...'
```
**Description:** Generic URI query failure for a nonexistent token.

---

### 10. **Token Does Not Exist** (8 errors - 0.2%)
```
Error: ('execution reverted: Token does not exist: 0x08c379a0...'
```
**Description:** Contract-specific message indicating the queried token doesn't exist.

---

## Minor Error Categories (< 1%)

### 11. Generic Revert Code `0xceea21b6` (7 errors)
### 12. Generic Revert Code `0xa14c4b50` (5 errors)
### 13. Another Revert Code Pattern (5 errors)
### 14. ERC3525 Invalid Token ID (4 errors)
### 15. Nonexistent Token (3 errors)
### 16. Generic Revert Code `0x0f3342be` (2 errors)
### 17. NOT_MINTED Execution Revert (2 errors)
### 18. Decode Contract Function Error (2 errors)
### 19. Token Does Not Exist (Different Format) (2 errors)
### 20. No Native Execution Revert (2 errors)

---

## Rare Errors (1 occurrence each)

- NFT不存在 (Chinese: "NFT does not exist")
- Multiple unknown revert codes: `0x44943622`, `0xe22e27eb...`, etc.
- URI not configured for category
- DexRoy: Contract does not accept ETH
- No token error
- TRC721Metadata URI query failure
- Token not exists
- UTF-8 decoding error
- TreeNFT URI query failure
- Nonexistent token (TreeNFT variant)
- VibeNft: URL not set
- Division by zero panic error
- RenaissRegistry: Nonexistent token

---

## Error Grouping by Root Cause

### **By Severity/Type:**

#### Critical (Token/Contract Issues) - ~49.0%
- Metadata fetch failed: 1,521
- Invalid/nonexistent tokens: 206 + 18 + 10 + 8 + 3 = 245
- No tokens minted: 158

#### Smart Contract Execution Failures - ~30.6%
- Execution reverted (generic): 935
- Various revert codes: 158 + 7 + 5 + 5 + 4 + 2 + 2 + 1 + 1 + 1 + 1 + 1 = 188

#### URI/Metadata Issues - ~14.3%
- Empty URI: 356
- Unsupported token URI: 154

#### Other/Rare Errors - ~0.1%
- All other errors: 1 each or pairs

---

## Analysis Notes

1. **Metadata Fetch Issues (42.6%):** The largest error category suggests many NFT metadata endpoints are either:
   - Permanently offline
   - Rate-limited or temporarily unavailable
   - Using unreliable or deprecated servers

2. **Smart Contract Execution (30.6%):** Suggests many contracts may be:
   - Buggy or poorly implemented
   - Revoked/suspended
   - Incompatible with standard ERC-721/ERC-1155 interfaces

3. **URI Problems (14.3%):** Empty or unsupported URIs indicate:
   - Incomplete contract implementations
   - Non-standard URI schemes
   - Pre-reveal or placeholder contracts

4. **Token Validity (13.6%):** Combined with "no_tokens_minted", indicates many entries are:
   - For deprecated/burned tokens
   - For recently created contracts with no mints
   - Invalid references

---

## Recommendations

1. **Classify contracts** based on error type to identify patterns
2. **Prioritize retry logic** for `metadata_fetch_failed` errors
3. **Flag contracts** with consistent execution reverts for manual review
4. **Group by error code** to identify contract implementation patterns
