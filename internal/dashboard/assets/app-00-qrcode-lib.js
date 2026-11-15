/* ==========================================================================
   app-00-qrcode-lib.js — part 00 of 16 of the dashboard bundle.

   QR CODE LIBRARY (minimal, byte mode)

   Every file in this directory is concatenated, in name order, into the
   single /app.js the page loads. They share one global scope, so a
   function declared here is visible to later parts — order matters.
   Keep one feature per file: a part that grows past ~900 lines is a
   signal to split it, not to let it grow (see assets_bundle_test.go).
   ========================================================================== */

// Minimal QR Code generator (byte mode, ECC L/M auto) for dashboard use.
// Compact implementation for short verification references (UTF-8 bytes).
(function (global) {
  'use strict';

  function QR8bitByte(data) { this.mode = 1; this.data = data; this.parsedData = []; for (var i = 0; i < data.length; i++) { var b = unescape(encodeURIComponent(data)).charCodeAt(i); this.parsedData.push(b); } }
  QR8bitByte.prototype = { getLength: function () { return this.parsedData.length; }, write: function (buffer) { for (var i = 0; i < this.parsedData.length; i++) buffer.put(this.parsedData[i], 8); } };

  var QRMode = { MODE_8BIT_BYTE: 1 };
  var QRErrorCorrectLevel = { L: 1, M: 0, Q: 3, H: 2 }; // values per QR spec mapping used below

  // Polynomial math and RS blocks (adapted compact form)
  var QRMath = {
    glog: function (n) { if (n < 1) throw new Error('glog'); return QRMath.LOG_TABLE[n]; },
    gexp: function (n) { while (n < 0) n += 255; while (n >= 256) n -= 255; return QRMath.EXP_TABLE[n]; },
    EXP_TABLE: new Array(256), LOG_TABLE: new Array(256)
  };
  (function () { for (var i = 0; i < 8; i++) QRMath.EXP_TABLE[i] = 1 << i; for (i = 8; i < 256; i++) QRMath.EXP_TABLE[i] = QRMath.EXP_TABLE[i - 4] ^ QRMath.EXP_TABLE[i - 5] ^ QRMath.EXP_TABLE[i - 6] ^ QRMath.EXP_TABLE[i - 8]; for (i = 0; i < 255; i++) QRMath.LOG_TABLE[QRMath.EXP_TABLE[i]] = i; })();

  function QRPolynomial(num, shift) {
    if (num.length == null) throw new Error(num.length + '/' + shift);
    var offset = 0; while (offset < num.length && num[offset] == 0) offset++;
    this.num = new Array(num.length - offset + shift);
    for (var i = 0; i < num.length - offset; i++) this.num[i] = num[i + offset];
  }
  QRPolynomial.prototype = {
    get: function (index) { return this.num[index]; }, getLength: function () { return this.num.length; },
    multiply: function (e) { var num = new Array(this.getLength() + e.getLength() - 1); for (var i = 0; i < this.getLength(); i++) for (var j = 0; j < e.getLength(); j++) num[i + j] ^= QRMath.gexp(QRMath.glog(this.get(i)) + QRMath.glog(e.get(j))); return new QRPolynomial(num, 0); },
    mod: function (e) { if (this.getLength() - e.getLength() < 0) return this; var ratio = QRMath.glog(this.get(0)) - QRMath.glog(e.get(0)); var num = new Array(this.getLength()); for (var i = 0; i < this.getLength(); i++) num[i] = this.get(i); for (i = 0; i < e.getLength(); i++) num[i] ^= QRMath.gexp(QRMath.glog(e.get(i)) + ratio); return new QRPolynomial(num, 0).mod(e); }
  };

  var QRRSBlock = {
    getRSBlocks: function (typeNumber, errorCorrectLevel) {
      var rsBlock = QRRSBlock.getRsBlockTable(typeNumber, errorCorrectLevel); if (!rsBlock) throw new Error('bad rs block');
      var length = rsBlock.length / 3, list = [];
      for (var i = 0; i < length; i++) { var count = rsBlock[i * 3 + 0], totalCount = rsBlock[i * 3 + 1], dataCount = rsBlock[i * 3 + 2]; for (var j = 0; j < count; j++) list.push({ totalCount: totalCount, dataCount: dataCount }); }
      return list;
    },
    // (typeNumber, ecLevel) -> [count,total,data,...] for versions 1-10, levels L/M/Q/H
    RS_BLOCK_TABLE: [
      // 1
      [1,26,19],[1,26,16],[1,26,13],[1,26,9],
      // 2
      [1,44,34],[1,44,28],[1,44,22],[1,44,16],
      // 3
      [1,70,55],[1,70,44],[2,35,17],[2,35,13],
      // 4
      [1,100,80],[2,50,32],[2,50,24],[4,25,9],
      // 5
      [1,134,108],[2,67,43],[2,33,15,2,34,16],[2,33,11,2,34,12],
      // 6
      [2,86,68],[4,43,27],[4,43,19],[4,43,15],
      // 7
      [2,98,78],[4,49,31],[2,32,14,4,33,15],[4,39,13,1,40,14],
      // 8
      [2,121,97],[2,60,38,2,61,39],[4,40,18,2,41,19],[4,40,14,2,41,15],
      // 9
      [2,146,116],[3,58,36,2,59,37],[4,36,16,4,37,17],[4,36,12,4,37,13],
      // 10
      [2,86,68,2,87,69],[4,69,43,1,70,44],[6,43,19,2,44,20],[6,43,15,2,44,16]
    ],
    getRsBlockTable: function (typeNumber, errorCorrectLevel) {
      // mapping: L=1, M=0, Q=3, H=2
      var idx = (typeNumber - 1) * 4 + errorCorrectLevel;
      return QRRSBlock.RS_BLOCK_TABLE[idx];
    }
  };

  function QRBitBuffer() { this.buffer = []; this.length = 0; }
  QRBitBuffer.prototype = {
    get: function (index) { var bufIndex = Math.floor(index / 8); return ((this.buffer[bufIndex] >>> (7 - index % 8)) & 1) == 1; },
    put: function (num, length) { for (var i = 0; i < length; i++) this.putBit(((num >>> (length - i - 1)) & 1) == 1); },
    getLengthInBits: function () { return this.length; },
    putBit: function (bit) { var bufIndex = Math.floor(this.length / 8); if (this.buffer.length <= bufIndex) this.buffer.push(0); if (bit) this.buffer[bufIndex] |= (0x80 >>> (this.length % 8)); this.length++; }
  };

  function QRUtil() {}
  QRUtil.PATTERN_POSITION_TABLE = [[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50]];
  QRUtil.G15 = (1<<10)|(1<<8)|(1<<5)|(1<<4)|(1<<2)|(1<<1)|(1<<0);
  QRUtil.G18 = (1<<12)|(1<<11)|(1<<10)|(1<<9)|(1<<8)|(1<<5)|(1<<2)|(1<<0);
  QRUtil.G15_MASK = (1<<14)|(1<<12)|(1<<10)|(1<<4)|(1<<1);
  QRUtil.getBCHTypeInfo = function (data) { var d = data << 10; while (QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G15) >= 0) d ^= (QRUtil.G15 << (QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G15))); return ((data << 10) | d) ^ QRUtil.G15_MASK; };
  QRUtil.getBCHTypeNumber = function (data) { var d = data << 12; while (QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G18) >= 0) d ^= (QRUtil.G18 << (QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G18))); return (data << 12) | d; };
  QRUtil.getBCHDigit = function (data) { var digit = 0; while (data != 0) { digit++; data >>>= 1; } return digit; };
  QRUtil.getPatternPosition = function (typeNumber) { return QRUtil.PATTERN_POSITION_TABLE[typeNumber - 1]; };
  QRUtil.getMask = function (maskPattern, i, j) { switch (maskPattern) { case 0: return (i + j) % 2 == 0; case 1: return i % 2 == 0; case 2: return j % 3 == 0; case 3: return (i + j) % 3 == 0; case 4: return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 == 0; case 5: return (i * j) % 2 + (i * j) % 3 == 0; case 6: return ((i * j) % 2 + (i * j) % 3) % 2 == 0; case 7: return ((i * j) % 3 + (i + j) % 2) % 2 == 0; default: throw new Error('mask'); } };
  QRUtil.getErrorCorrectPolynomial = function (ecLength) { var a = new QRPolynomial([1], 0); for (var i = 0; i < ecLength; i++) a = a.multiply(new QRPolynomial([1, QRMath.gexp(i)], 0)); return a; };
  QRUtil.getLengthInBits = function (mode, type) { if (1 <= type && type < 10) return 8; else if (type < 27) return 16; else return 16; };

  function QRCodeModel(typeNumber, errorCorrectLevel) {
    this.typeNumber = typeNumber; this.errorCorrectLevel = errorCorrectLevel; this.modules = null; this.moduleCount = 0; this.dataCache = null; this.dataList = [];
  }
  QRCodeModel.prototype = {
    addData: function (data) { this.dataList.push(new QR8bitByte(data)); this.dataCache = null; },
    isDark: function (row, col) { return this.modules[row][col]; }, getModuleCount: function () { return this.moduleCount; },
    make: function () { this.makeImpl(false, this.getBestMaskPattern()); },
    makeImpl: function (test, maskPattern) {
      this.moduleCount = this.typeNumber * 4 + 17; this.modules = new Array(this.moduleCount);
      for (var row = 0; row < this.moduleCount; row++) { this.modules[row] = new Array(this.moduleCount); for (var col = 0; col < this.moduleCount; col++) this.modules[row][col] = null; }
      this.setupPositionProbePattern(0, 0); this.setupPositionProbePattern(this.moduleCount - 7, 0); this.setupPositionProbePattern(0, this.moduleCount - 7);
      this.setupPositionAdjustPattern(); this.setupTimingPattern(); this.setupTypeInfo(test, maskPattern);
      if (this.typeNumber >= 7) this.setupTypeNumber(test);
      if (this.dataCache == null) this.dataCache = QRCodeModel.createData(this.typeNumber, this.errorCorrectLevel, this.dataList);
      this.mapData(this.dataCache, maskPattern);
    },
    setupPositionProbePattern: function (row, col) {
      for (var r = -1; r <= 7; r++) { if (row + r <= -1 || this.moduleCount <= row + r) continue; for (var c = -1; c <= 7; c++) { if (col + c <= -1 || this.moduleCount <= col + c) continue; if ((0 <= r && r <= 6 && (c == 0 || c == 6)) || (0 <= c && c <= 6 && (r == 0 || r == 6)) || (2 <= r && r <= 4 && 2 <= c && c <= 4)) this.modules[row + r][col + c] = true; else this.modules[row + r][col + c] = false; } }
    },
    getBestMaskPattern: function () { var minLost = 0, pattern = 0; for (var i = 0; i < 8; i++) { this.makeImpl(true, i); var lost = QRUtil.getLostPoint(this); if (i == 0 || minLost > lost) { minLost = lost; pattern = i; } } return pattern; },
    setupTimingPattern: function () { for (var r = 8; r < this.moduleCount - 8; r++) if (this.modules[r][6] == null) this.modules[r][6] = (r % 2 == 0); for (var c = 8; c < this.moduleCount - 8; c++) if (this.modules[6][c] == null) this.modules[6][c] = (c % 2 == 0); },
    setupPositionAdjustPattern: function () { var pos = QRUtil.getPatternPosition(this.typeNumber); for (var i = 0; i < pos.length; i++) for (var j = 0; j < pos.length; j++) { var row = pos[i], col = pos[j]; if (this.modules[row][col] != null) continue; for (var r = -2; r <= 2; r++) for (var c = -2; c <= 2; c++) this.modules[row + r][col + c] = (r == -2 || r == 2 || c == -2 || c == 2 || (r == 0 && c == 0)); } },
    setupTypeNumber: function (test) { var bits = QRUtil.getBCHTypeNumber(this.typeNumber); for (var i = 0; i < 18; i++) { var mod = (!test && ((bits >> i) & 1) == 1); this.modules[Math.floor(i / 3)][i % 3 + this.moduleCount - 8 - 3] = mod; this.modules[i % 3 + this.moduleCount - 8 - 3][Math.floor(i / 3)] = mod; } },
    setupTypeInfo: function (test, maskPattern) { var data = (this.errorCorrectLevel << 3) | maskPattern; var bits = QRUtil.getBCHTypeInfo(data); for (var i = 0; i < 15; i++) { var mod = (!test && ((bits >> i) & 1) == 1); if (i < 6) this.modules[i][8] = mod; else if (i < 8) this.modules[i + 1][8] = mod; else this.modules[this.moduleCount - 15 + i][8] = mod; if (i < 8) this.modules[8][this.moduleCount - i - 1] = mod; else if (i < 9) this.modules[8][15 - i - 1 + 1] = mod; else this.modules[8][15 - i - 1] = mod; } this.modules[this.moduleCount - 8][8] = (!test); },
    mapData: function (data, maskPattern) {
      var inc = -1, row = this.moduleCount - 1, bitIndex = 7, byteIndex = 0;
      for (var col = this.moduleCount - 1; col > 0; col -= 2) { if (col == 6) col--; while (true) { for (var c = 0; c < 2; c++) { if (this.modules[row][col - c] == null) { var dark = false; if (byteIndex < data.length) dark = (((data[byteIndex] >>> bitIndex) & 1) == 1); var mask = QRUtil.getMask(maskPattern, row, col - c); if (mask) dark = !dark; this.modules[row][col - c] = dark; bitIndex--; if (bitIndex == -1) { byteIndex++; bitIndex = 7; } } } row += inc; if (row < 0 || this.moduleCount <= row) { row -= inc; inc = -inc; break; } } }
    }
  };
  QRUtil.getLostPoint = function (qrCode) {
    var moduleCount = qrCode.getModuleCount(), lostPoint = 0;
    for (var row = 0; row < moduleCount; row++) for (var col = 0; col < moduleCount; col++) {
      var sameCount = 0, dark = qrCode.isDark(row, col);
      for (var r = -1; r <= 1; r++) { if (row + r < 0 || moduleCount <= row + r) continue; for (var c = -1; c <= 1; c++) { if (col + c < 0 || moduleCount <= col + c) continue; if (r == 0 && c == 0) continue; if (dark == qrCode.isDark(row + r, col + c)) sameCount++; } }
      if (sameCount > 5) lostPoint += (3 + sameCount - 5);
    }
    for (row = 0; row < moduleCount - 1; row++) for (col = 0; col < moduleCount - 1; col++) { var count = 0; if (qrCode.isDark(row, col)) count++; if (qrCode.isDark(row + 1, col)) count++; if (qrCode.isDark(row, col + 1)) count++; if (qrCode.isDark(row + 1, col + 1)) count++; if (count == 0 || count == 4) lostPoint += 3; }
    for (row = 0; row < moduleCount; row++) for (col = 0; col < moduleCount - 6; col++) if (qrCode.isDark(row, col) && !qrCode.isDark(row, col + 1) && qrCode.isDark(row, col + 2) && qrCode.isDark(row, col + 3) && qrCode.isDark(row, col + 4) && !qrCode.isDark(row, col + 5) && qrCode.isDark(row, col + 6)) lostPoint += 40;
    for (col = 0; col < moduleCount; col++) for (row = 0; row < moduleCount - 6; row++) if (qrCode.isDark(row, col) && !qrCode.isDark(row + 1, col) && qrCode.isDark(row + 2, col) && qrCode.isDark(row + 3, col) && qrCode.isDark(row + 4, col) && !qrCode.isDark(row + 5, col) && qrCode.isDark(row + 6, col)) lostPoint += 40;
    var darkCount = 0; for (col = 0; col < moduleCount; col++) for (row = 0; row < moduleCount; row++) if (qrCode.isDark(row, col)) darkCount++;
    var ratio = Math.abs(100 * darkCount / moduleCount / moduleCount - 50) / 5; lostPoint += ratio * 10;
    return lostPoint;
  };
  QRCodeModel.createData = function (typeNumber, errorCorrectLevel, dataList) {
    var rsBlocks = QRRSBlock.getRSBlocks(typeNumber, errorCorrectLevel), buffer = new QRBitBuffer();
    for (var i = 0; i < dataList.length; i++) { var data = dataList[i]; buffer.put(4, 4); buffer.put(data.getLength(), QRUtil.getLengthInBits(1, typeNumber)); data.write(buffer); }
    var totalDataCount = 0; for (i = 0; i < rsBlocks.length; i++) totalDataCount += rsBlocks[i].dataCount;
    if (buffer.getLengthInBits() > totalDataCount * 8) throw new Error('code length overflow');
    if (buffer.getLengthInBits() + 4 <= totalDataCount * 8) buffer.put(0, 4);
    while (buffer.getLengthInBits() % 8 != 0) buffer.putBit(false);
    while (true) { if (buffer.getLengthInBits() >= totalDataCount * 8) break; buffer.put(0xEC, 8); if (buffer.getLengthInBits() >= totalDataCount * 8) break; buffer.put(0x11, 8); }
    return QRCodeModel.createBytes(buffer, rsBlocks);
  };
  QRCodeModel.createBytes = function (buffer, rsBlocks) {
    var offset = 0, maxDcCount = 0, maxEcCount = 0, dcdata = new Array(rsBlocks.length), ecdata = new Array(rsBlocks.length);
    for (var r = 0; r < rsBlocks.length; r++) {
      var dcCount = rsBlocks[r].dataCount, ecCount = rsBlocks[r].totalCount - dcCount; maxDcCount = Math.max(maxDcCount, dcCount); maxEcCount = Math.max(maxEcCount, ecCount);
      dcdata[r] = new Array(dcCount); for (var i = 0; i < dcdata[r].length; i++) dcdata[r][i] = 0xff & buffer.buffer[i + offset]; offset += dcCount;
      var rsPoly = QRUtil.getErrorCorrectPolynomial(ecCount), rawPoly = new QRPolynomial(dcdata[r], rsPoly.getLength() - 1), modPoly = rawPoly.mod(rsPoly);
      ecdata[r] = new Array(rsPoly.getLength() - 1); for (i = 0; i < ecdata[r].length; i++) { var modIndex = i + modPoly.getLength() - ecdata[r].length; ecdata[r][i] = (modIndex >= 0) ? modPoly.get(modIndex) : 0; }
    }
    var totalCodeCount = 0; for (r = 0; r < rsBlocks.length; r++) totalCodeCount += rsBlocks[r].totalCount;
    var data = new Array(totalCodeCount), index = 0;
    for (i = 0; i < maxDcCount; i++) for (r = 0; r < rsBlocks.length; r++) if (i < dcdata[r].length) data[index++] = dcdata[r][i];
    for (i = 0; i < maxEcCount; i++) for (r = 0; r < rsBlocks.length; r++) if (i < ecdata[r].length) data[index++] = ecdata[r][i];
    return data;
  };

  function makeModel(text, ecLevelName) {
    var ec = (ecLevelName === 'H') ? 2 : (ecLevelName === 'Q') ? 3 : (ecLevelName === 'M') ? 0 : 1; // L default
    for (var typeNumber = 1; typeNumber <= 10; typeNumber++) {
      try {
        var qr = new QRCodeModel(typeNumber, ec);
        qr.addData(text);
        qr.make();
        return qr;
      } catch (e) {
        if (typeNumber === 10) throw e;
      }
    }
    throw new Error('QR too large');
  }

  function drawToCanvas(canvas, text, opts) {
    opts = opts || {};
    var qr = makeModel(String(text || ''), opts.ecLevel || 'M');
    var ctx = canvas.getContext('2d'); if (!ctx) return false;
    var count = qr.getModuleCount();
    var size = Math.min(canvas.width || 132, canvas.height || 132);
    var margin = opts.margin != null ? opts.margin : 4;
    var cell = Math.max(1, Math.floor((size - margin * 2) / count));
    var qrSize = cell * count;
    var offset = Math.floor((size - qrSize) / 2);
    ctx.fillStyle = opts.light || '#ffffff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = opts.dark || '#111827';
    for (var r = 0; r < count; r++) for (var c = 0; c < count; c++) if (qr.isDark(r, c)) ctx.fillRect(offset + c * cell, offset + r * cell, cell, cell);
    return true;
  }

  global.SiftQRCode = { makeModel: makeModel, drawToCanvas: drawToCanvas };
})(typeof window !== 'undefined' ? window : this);
