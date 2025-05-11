const querystring = require('node:querystring');

const web_address = "https://server.blayzegames.com/OnlineAccountSystem/fairplay_spec.php";
const magic = "1983031920131006";

const SEC_SIZE = 16;

class FairCollection {
    static #off1 = 0;
    static #off2 = 0;
    static #sec1 = new Uint8Array(SEC_SIZE);
    static #sec2 = new Uint8Array(SEC_SIZE);
    static #response = "";
    static #enabled = false;

    static async #init_request() {
        const response = await fetch(
            web_address, {
                method: 'POST',
                headers: {
                    accept: '*/*',
                    'accept-language': 'en-US,en;q=0.9',
                    'content-type': 'application/x-www-form-urlencoded'
                },
                body: querystring.stringify({magic: magic}),
            }
        );
        if (!response.ok) {
            //console.error(response.statusText);
            throw Error(response.statusText);
        }
        this.#response = await response.text();
        // console.log(this.#response);
    }

    /*static #loc_7_0(str) {
        const buf = Buffer.from(FairCollection.#response, 'hex');
        const bytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
        let bytes_index = 0;

        const new_bytes = new Uint8Array(str.length / 2);
        let new_bytes_index = 0;

        while (bytes_index < bytes.length) {
            let b1 = bytes[bytes_index];
            let b2 = bytes[bytes_index + 1];
    
            bytes_index += 2;
    
            if (b1 > 0x60) {
                b1 = b1 - 0x20;
            }
            if (b2 > 0x60) {
                b2 = b2 - 0x20;
            }
    
            let b11 = -0x37;
            if (b1 < 0x41) {
                b11 = 0;
            }
            let b22 = -0x37;
            if (b2 < 0x41) {
                b22 = -0x30;
            }
    
            new_bytes_index++;
            new_bytes[new_bytes_index] = (b2 + (b11 + b1) * 16 + b22) & 0xFF;
        }
        return new_bytes;
    }*/
    
    static #init_data() {
        // const bytes = FairCollection.#loc_7_0(FairCollection.#response);
        
        const buf = Buffer.from(FairCollection.#response, 'hex');
        const bytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);

        if (bytes[1] !== 0)
            return;

        FairCollection.#off1 = bytes[3];
        FairCollection.#off2 = bytes[4];

        for (let i = 0; i < SEC_SIZE; ++i) {
            FairCollection.#sec1[i] = bytes[i + 5];
            FairCollection.#sec2[i] = bytes[i + 5 + SEC_SIZE];
        }
        FairCollection.#enabled = true;
    }
    
    /*static #transform_arraybuffer(buf, sec, off) {
        const bytes = new Uint8Array(buf);
        let i = 0, k = 0;
        while (i < bytes.length) {
            const sec_index = off + (k >>> 1);
            if (k & 1 !== 0) {
                bytes[i] ^= sec[sec_index] >>> 4;
            } else {
                bytes[i] ^= sec[sec_index] & 0xF;
            }
            ++i;
            ++k;
            if (k >= sec.length)
                k = 0;
        }
    }*/
    
    static #transform_arraybuffer(buf, sec, off) {
        const bytes = new Uint8Array(buf);
        let k = 0;
        for (let i = 0; i < bytes.length; ++i) {
            const sec_index = off + (k >>> 1);
            if (k & 1 !== 0) {
                bytes[i] ^= sec[sec_index] >>> 4;
            } else {
                bytes[i] ^= sec[sec_index] & 0xF;
            }
            ++k;
            if (k >= sec.length)
                k = 0;
        }
    }

    static async InitOperation() {
        if (!FairCollection.#enabled) {
            await this.#init_request();
            this.#init_data();
        }
    }

    static GetEncryptedDouble(value) {
        if (!FairCollection.#enabled)
            return value

        const arr = new Float64Array(1);
        arr[0] = value;
        this.#transform_arraybuffer(arr.buffer, FairCollection.#sec1, FairCollection.#off1);
        return arr[0];
    }
    static GetDecryptedDouble(value) {
        if (!FairCollection.#enabled)
            return value

        const arr = new Float64Array(1);
        arr[0] = value;
        this.#transform_arraybuffer(arr.buffer, FairCollection.#sec2, FairCollection.#off2);
        return arr[0];
    }

    static GetEncryptedFloat(value) {
        if (!FairCollection.#enabled)
            return value

        const arr = new Float32Array(1);
        arr[0] = value;
        this.#transform_arraybuffer(arr.buffer, FairCollection.#sec1, FairCollection.#off1);
        return arr[0];
    }
    static GetDecryptedFloat(value) {
        if (!FairCollection.#enabled)
            return value

        const arr = new Float32Array(1);
        arr[0] = value;
        this.#transform_arraybuffer(arr.buffer, FairCollection.#sec2, FairCollection.#off2);
        return arr[0];
    }

    static GetEncryptedInteger(value) {
        if (!FairCollection.#enabled)
            return value

        const arr = new Int32Array(1);
        arr[0] = value;
        this.#transform_arraybuffer(arr.buffer, FairCollection.#sec1, FairCollection.#off1);
        return arr[0];
    }
    static GetDecryptedInteger(value) {
        if (!FairCollection.#enabled)
            return value

        const arr = new Int32Array(1);
        arr[0] = value;
        this.#transform_arraybuffer(arr.buffer, FairCollection.#sec2, FairCollection.#off2);
        return arr[0];
    }

    static GetEncryptedString(value) {
        if (!FairCollection.#enabled)
            return value

        var arr = new TextEncoder().encode(value);
        this.#transform_arraybuffer(arr.buffer, FairCollection.#sec1, FairCollection.#off1);
        return new TextDecoder().decode(arr);
    }
    static GetDecryptedString(value) {
        if (!FairCollection.#enabled)
            return value

        var arr = new TextEncoder().encode(value);
        this.#transform_arraybuffer(arr.buffer, FairCollection.#sec2, FairCollection.#off2);
        return new TextDecoder().decode(arr);
    }

    static GetEncryptedVector2(value) {
        if (!FairCollection.#enabled)
            return value

        return {
            x: this.GetEncryptedFloat(value.x),
            y: this.GetEncryptedFloat(value.y)
        }
    }
    static GetDecryptedVector2(value) {
        if (!FairCollection.#enabled)
            return value

        return {
            x: this.GetDecryptedFloat(value.x),
            y: this.GetDecryptedFloat(value.y)
        }
    }

    static GetEncryptedVector2Int(value) {
        if (!FairCollection.#enabled)
            return value

        return {
            x: this.GetEncryptedInteger(value.x),
            y: this.GetEncryptedInteger(value.y)
        }
    }
    static GetDecryptedVector2Int(value) {
        if (!FairCollection.#enabled)
            return value

        return {
            x: this.GetDecryptedInteger(value.x),
            y: this.GetDecryptedInteger(value.y)
        }
    }

    static GetEncryptedVector3(value) {
        if (!FairCollection.#enabled)
            return value

        return {
            x: this.GetEncryptedFloat(value.x),
            y: this.GetEncryptedFloat(value.y),
            z: this.GetEncryptedFloat(value.z)
        }
    }
    static GetDecryptedVector3(value) {
        if (!FairCollection.#enabled)
            return value

        return {
            x: this.GetDecryptedFloat(value.x),
            y: this.GetDecryptedFloat(value.y),
            z: this.GetDecryptedFloat(value.z)
        }
    }

    static GetEncryptedVector3Int(value) {
        if (!FairCollection.#enabled)
            return value

        return {
            x: this.GetEncryptedInteger(value.x),
            y: this.GetEncryptedInteger(value.y),
            z: this.GetEncryptedInteger(value.z)
        }
    }
    static GetDecryptedVector3Int(value) {
        if (!FairCollection.#enabled)
            return value

        return {
            x: this.GetDecryptedInteger(value.x),
            y: this.GetDecryptedInteger(value.y),
            z: this.GetDecryptedInteger(value.z)
        }
    }

    static GetEncryptedVector4(value) {
        if (!FairCollection.#enabled)
            return value

        return {
            x: this.GetEncryptedFloat(value.x),
            y: this.GetEncryptedFloat(value.y),
            z: this.GetEncryptedFloat(value.z),
            w: this.GetEncryptedFloat(value.w)
        }
    }
    static GetDecryptedVector4(value) {
        if (!FairCollection.#enabled)
            return value

        return {
            x: this.GetDecryptedFloat(value.x),
            y: this.GetDecryptedFloat(value.y),
            z: this.GetDecryptedFloat(value.z),
            w: this.GetDecryptedFloat(value.w)
        }
    }
}





module.exports = FairCollection;
