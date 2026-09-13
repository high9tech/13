/* HIGH TECH PS - Int64 Precision Handling Header */

function int64(low, hi = 0) {
    this.low = (low >>> 0);
    this.hi = (hi >>> 0);
    this.backing = null;

    this.add32inplace = function (val) {
        let val32 = val >>> 0;
        let new_lo = ((this.low >>> 0) + val32) >>> 0;
        let new_hi = this.hi >>> 0;
        if (new_lo < (this.low >>> 0)) { 
            new_hi = (new_hi + 1) >>> 0; 
        }
        this.hi = new_hi;
        this.low = new_lo;
    };

    this.add32 = function (val) {
        let val32 = val >>> 0;
        let low32 = this.low >>> 0;
        let new_lo = (low32 + val32) >>> 0;
        let new_hi = this.hi >>> 0;
        if (new_lo < low32) { 
            new_hi = (new_hi + 1) >>> 0; 
        }
        return new int64(new_lo, new_hi);
    };

    this.sub32 = function (val) {
        let val32 = val >>> 0;
        let low32 = this.low >>> 0;
        let new_lo = (low32 - val32) >>> 0;
        let new_hi = this.hi >>> 0;
        if (val32 > low32) { 
            new_hi = (new_hi - 1) >>> 0; 
        }
        return new int64(new_lo, new_hi);
    };

    this.sub32inplace = function (val) {
        let val32 = val >>> 0;
        let low32 = this.low >>> 0;
        let new_lo = (low32 - val32) >>> 0;
        let new_hi = this.hi >>> 0;
        if (val32 > low32) { 
            new_hi = (new_hi - 1) >>> 0; 
        }
        this.hi = new_hi;
        this.low = new_lo;
    };

    this.and32 = function (val) {
        return new int64((this.low & val) >>> 0, this.hi);
    };

    this.and64 = function (vallo, valhi) {
        return new int64((this.low & vallo) >>> 0, (this.hi & valhi) >>> 0);
    };

    this.toString = function (radix = 16) {
        let lo_str = (this.low >>> 0).toString(radix);
        let hi_str = (this.hi >>> 0).toString(radix);
        
        if ((this.hi >>> 0) === 0) {
            return lo_str;
        }
        
        if (radix === 16) {
            return hi_str + lo_str.padStart(8, '0');
        }
        
        return (BigInt(this.hi >>> 0) * 4294967296n + BigInt(this.low >>> 0)).toString(radix);
    };

    return this;
}

globalThis.int64 = int64;

export { int64 };
export default int64;
