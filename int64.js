/* HIGH TECH PS - Int64 Precision Handling Header */
function zeroFill(number, width) {
    width -= number.toString().length;
    if (width > 0) {
        return new Array(width + (/\./.test(number) ? 2 : 1)).join('0') + number;
    }
    return number + "";
}

function int64(low, hi) {
    this.low = (low >>> 0);
    this.hi = (hi >>> 0);
    this.backing = null;

    this.add32inplace = function (val) {
        let new_lo = (((this.low >>> 0) + val) & 0xFFFFFFFF) >>> 0;
        let new_hi = (this.hi >>> 0);
        if (new_lo < this.low) { new_hi++; }
        this.hi = new_hi;
        this.low = new_lo;
    };

    this.add32 = function (val) {
        let new_lo = (((this.low >>> 0) + val) & 0xFFFFFFFF) >>> 0;
        let new_hi = (this.hi >>> 0);
        if (new_lo < this.low) { new_hi++; }
        return new int64(new_lo, new_hi);
    };

    this.sub32 = function (val) {
        let new_lo = (((this.low >>> 0) - val) & 0xFFFFFFFF) >>> 0;
        let new_hi = (this.hi >>> 0);
        if (new_lo > (this.low & 0xFFFFFFFF)) { new_hi--; }
        return new int64(new_lo, new_hi);
    };

    this.sub32inplace = function (val) {
        let new_lo = (((this.low >>> 0) - val) & 0xFFFFFFFF) >>> 0;
        let new_hi = (this.hi >>> 0);
        if (new_lo > (this.low & 0xFFFFFFFF)) { new_hi--; }
        this.hi = new_hi;
        this.low = new_lo;
    };

    this.and32 = function (val) {
        return new int64(this.low & val, this.hi);
    };

    this.and64 = function (vallo, valhi) {
        return new int64(this.low & vallo, this.hi & valhi);
    };

    this.toString = function (radix = 16) {
        let lo_str = (this.low >>> 0).toString(radix);
        let hi_str = (this.hi >>> 0).toString(radix);
        if (this.hi == 0) {
            return lo_str;
        } else {
            const width = radix === 16 ? 8 : Math.ceil(32 / Math.log2(radix));
            lo_str = zeroFill(lo_str, width);
        }
        return hi_str + lo_str;
    };

    return this;
}

globalThis.int64 = int64;

export { int64 };
export default int64;
