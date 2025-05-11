/**
 * FairCollection - A utility class for secure data handling for Bullet Force.
 * 
 * Provides encryption and decryption utilities for various data types 
 * including numbers, strings, and vector objects.
 */

const WEB_ADDRESS = "https://server.blayzegames.com/OnlineAccountSystem/fairplay_spec.php";
const MAGIC = "1983031920131006";
const SEC_SIZE = 16;

class FairCollection {
    static #off1 = 0;
    static #off2 = 0;
    static #sec1 = new Uint8Array(SEC_SIZE);
    static #sec2 = new Uint8Array(SEC_SIZE);
    static #response = "";
    static #enabled = false;

    /**
     * Makes an initialization request to the server.
     * @private
     */
    static async #initRequest() {
        try {
            const params = new URLSearchParams();
            params.append('magic', MAGIC);

            const response = await fetch(
                WEB_ADDRESS, {
                    method: 'POST',
                    headers: {
                        accept: '*/*',
                        'accept-language': 'en-US,en;q=0.9',
                        'content-type': 'application/x-www-form-urlencoded'
                    },
                    body: params.toString(),
                }
            );
            
            if (!response.ok) {
                throw Error(response.statusText);
            }
            
            this.#response = await response.text();
        } catch (error) {
            console.error("FairCollection initialization failed:", error);
            throw error;
        }
    }
    
    /**
     * Initializes internal data structures from the server response.
     * @private
     */
    static #initData() {
        const bytes = this.#hexStringToUint8Array(this.#response);

        if (bytes[1] !== 0) {
            return;
        }

        this.#off1 = bytes[3];
        this.#off2 = bytes[4];

        for (let i = 0; i < SEC_SIZE; ++i) {
            this.#sec1[i] = bytes[i + 5];
            this.#sec2[i] = bytes[i + 5 + SEC_SIZE];
        }
        
        this.#enabled = true;
    }
    
    /**
     * Converts a hex string to Uint8Array.
     * @private
     * @param {string} hexString - The hex string to convert
     * @returns {Uint8Array} - The resulting byte array
     */
    static #hexStringToUint8Array(hexString) {
        if (hexString.length % 2 !== 0) {
            throw new Error('Hex string must have an even number of characters');
        }
        
        const bytes = new Uint8Array(hexString.length / 2);
        
        for (let i = 0; i < hexString.length; i += 2) {
            bytes[i / 2] = parseInt(hexString.substring(i, i + 2), 16);
        }
        
        return bytes;
    }
    
    /**
     * Transforms an ArrayBuffer using the security parameters.
     * @private
     * @param {ArrayBuffer} buf - The buffer to transform
     * @param {Uint8Array} sec - The security array to use
     * @param {number} off - The offset to use
     */
    static #transformArrayBuffer(buf, sec, off) {
        const bytes = new Uint8Array(buf);
        let k = 0;
        
        for (let i = 0; i < bytes.length; ++i) {
            const secIndex = off + (k >>> 1);
            if (k & 1) {
                bytes[i] ^= sec[secIndex] >>> 4;
            } else {
                bytes[i] ^= sec[secIndex] & 0xF;
            }
            ++k;
            if (k >= sec.length) {
                k = 0;
            }
        }
    }

    /**
     * Initializes the FairCollection system.
     * Must be called before using any encryption/decryption methods.
     * @returns {Promise<void>}
     */
    static async InitOperation() {
        if (!this.#enabled) {
            await this.#initRequest();
            this.#initData();
        }
    }

    /**
     * Encrypts a double precision floating point number.
     * @param {number} value - The value to encrypt
     * @returns {number} - The encrypted value
     */
    static GetEncryptedDouble(value) {
        if (!this.#enabled) {
            return value;
        }

        const arr = new Float64Array(1);
        arr[0] = value;
        this.#transformArrayBuffer(arr.buffer, this.#sec1, this.#off1);
        return arr[0];
    }
    
    /**
     * Decrypts a double precision floating point number.
     * @param {number} value - The value to decrypt
     * @returns {number} - The decrypted value
     */
    static GetDecryptedDouble(value) {
        if (!this.#enabled) {
            return value;
        }

        const arr = new Float64Array(1);
        arr[0] = value;
        this.#transformArrayBuffer(arr.buffer, this.#sec2, this.#off2);
        return arr[0];
    }

    /**
     * Encrypts a single precision floating point number.
     * @param {number} value - The value to encrypt
     * @returns {number} - The encrypted value
     */
    static GetEncryptedFloat(value) {
        if (!this.#enabled) {
            return value;
        }

        const arr = new Float32Array(1);
        arr[0] = value;
        this.#transformArrayBuffer(arr.buffer, this.#sec1, this.#off1);
        return arr[0];
    }
    
    /**
     * Decrypts a single precision floating point number.
     * @param {number} value - The value to decrypt
     * @returns {number} - The decrypted value
     */
    static GetDecryptedFloat(value) {
        if (!this.#enabled) {
            return value;
        }

        const arr = new Float32Array(1);
        arr[0] = value;
        this.#transformArrayBuffer(arr.buffer, this.#sec2, this.#off2);
        return arr[0];
    }

    /**
     * Encrypts an integer.
     * @param {number} value - The value to encrypt
     * @returns {number} - The encrypted value
     */
    static GetEncryptedInteger(value) {
        if (!this.#enabled) {
            return value;
        }

        const arr = new Int32Array(1);
        arr[0] = value;
        this.#transformArrayBuffer(arr.buffer, this.#sec1, this.#off1);
        return arr[0];
    }
    
    /**
     * Decrypts an integer.
     * @param {number} value - The value to decrypt
     * @returns {number} - The decrypted value
     */
    static GetDecryptedInteger(value) {
        if (!this.#enabled) {
            return value;
        }

        const arr = new Int32Array(1);
        arr[0] = value;
        this.#transformArrayBuffer(arr.buffer, this.#sec2, this.#off2);
        return arr[0];
    }

    /**
     * Encrypts a string.
     * @param {string} value - The string to encrypt
     * @returns {string} - The encrypted string
     */
    static GetEncryptedString(value) {
        if (!this.#enabled) {
            return value;
        }

        const arr = new TextEncoder().encode(value);
        this.#transformArrayBuffer(arr.buffer, this.#sec1, this.#off1);
        return new TextDecoder().decode(arr);
    }
    
    /**
     * Decrypts a string.
     * @param {string} value - The string to decrypt
     * @returns {string} - The decrypted string
     */
    static GetDecryptedString(value) {
        if (!this.#enabled) {
            return value;
        }

        const arr = new TextEncoder().encode(value);
        this.#transformArrayBuffer(arr.buffer, this.#sec2, this.#off2);
        return new TextDecoder().decode(arr);
    }

    /**
     * Encrypts a 2D vector.
     * @param {Object} value - The vector to encrypt {x, y}
     * @returns {Object} - The encrypted vector
     */
    static GetEncryptedVector2(value) {
        if (!this.#enabled) {
            return value;
        }

        return {
            x: this.GetEncryptedFloat(value.x),
            y: this.GetEncryptedFloat(value.y)
        };
    }
    
    /**
     * Decrypts a 2D vector.
     * @param {Object} value - The vector to decrypt {x, y}
     * @returns {Object} - The decrypted vector
     */
    static GetDecryptedVector2(value) {
        if (!this.#enabled) {
            return value;
        }

        return {
            x: this.GetDecryptedFloat(value.x),
            y: this.GetDecryptedFloat(value.y)
        };
    }

    /**
     * Encrypts a 2D integer vector.
     * @param {Object} value - The vector to encrypt {x, y}
     * @returns {Object} - The encrypted vector
     */
    static GetEncryptedVector2Int(value) {
        if (!this.#enabled) {
            return value;
        }

        return {
            x: this.GetEncryptedInteger(value.x),
            y: this.GetEncryptedInteger(value.y)
        };
    }
    
    /**
     * Decrypts a 2D integer vector.
     * @param {Object} value - The vector to decrypt {x, y}
     * @returns {Object} - The decrypted vector
     */
    static GetDecryptedVector2Int(value) {
        if (!this.#enabled) {
            return value;
        }

        return {
            x: this.GetDecryptedInteger(value.x),
            y: this.GetDecryptedInteger(value.y)
        };
    }

    /**
     * Encrypts a 3D vector.
     * @param {Object} value - The vector to encrypt {x, y, z}
     * @returns {Object} - The encrypted vector
     */
    static GetEncryptedVector3(value) {
        if (!this.#enabled) {
            return value;
        }

        return {
            x: this.GetEncryptedFloat(value.x),
            y: this.GetEncryptedFloat(value.y),
            z: this.GetEncryptedFloat(value.z)
        };
    }
    
    /**
     * Decrypts a 3D vector.
     * @param {Object} value - The vector to decrypt {x, y, z}
     * @returns {Object} - The decrypted vector
     */
    static GetDecryptedVector3(value) {
        if (!this.#enabled) {
            return value;
        }

        return {
            x: this.GetDecryptedFloat(value.x),
            y: this.GetDecryptedFloat(value.y),
            z: this.GetDecryptedFloat(value.z)
        };
    }

    /**
     * Encrypts a 3D integer vector.
     * @param {Object} value - The vector to encrypt {x, y, z}
     * @returns {Object} - The encrypted vector
     */
    static GetEncryptedVector3Int(value) {
        if (!this.#enabled) {
            return value;
        }

        return {
            x: this.GetEncryptedInteger(value.x),
            y: this.GetEncryptedInteger(value.y),
            z: this.GetEncryptedInteger(value.z)
        };
    }
    
    /**
     * Decrypts a 3D integer vector.
     * @param {Object} value - The vector to decrypt {x, y, z}
     * @returns {Object} - The decrypted vector
     */
    static GetDecryptedVector3Int(value) {
        if (!this.#enabled) {
            return value;
        }

        return {
            x: this.GetDecryptedInteger(value.x),
            y: this.GetDecryptedInteger(value.y),
            z: this.GetDecryptedInteger(value.z)
        };
    }

    /**
     * Encrypts a 4D vector.
     * @param {Object} value - The vector to encrypt {x, y, z, w}
     * @returns {Object} - The encrypted vector
     */
    static GetEncryptedVector4(value) {
        if (!this.#enabled) {
            return value;
        }

        return {
            x: this.GetEncryptedFloat(value.x),
            y: this.GetEncryptedFloat(value.y),
            z: this.GetEncryptedFloat(value.z),
            w: this.GetEncryptedFloat(value.w)
        };
    }
    
    /**
     * Decrypts a 4D vector.
     * @param {Object} value - The vector to decrypt {x, y, z, w}
     * @returns {Object} - The decrypted vector
     */
    static GetDecryptedVector4(value) {
        if (!this.#enabled) {
            return value;
        }

        return {
            x: this.GetDecryptedFloat(value.x),
            y: this.GetDecryptedFloat(value.y),
            z: this.GetDecryptedFloat(value.z),
            w: this.GetDecryptedFloat(value.w)
        };
    }
}

// For browsers, expose to global scope
if (typeof window !== 'undefined') {
    window.FairCollection = FairCollection;
}
