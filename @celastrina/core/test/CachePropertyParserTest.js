/*
 * Copyright (c) 2020, Robert R Murrell.
 *
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
const {instanceOfCelastrinaType,CacheProperty, CachePropertyParser} = require("../Core");
const assert = require("assert");

describe("CachePropertyParser", () => {
	describe("#_create(_CacheProperty)", () => {
		it("should create using ttl and unit.", async () => {
			let _CacheProperty = {_content: {type: "application/vnd.celastrinajs.attribute+json;CacheProperty"},
									key: "property-key-one",
									ttl: 2,
									unit: "seconds"};
			let _parser = new CachePropertyParser();
			let _cache = await _parser._create(_CacheProperty);
			assert.strictEqual(_cache != null, true, "Expected no null.");
			assert.strictEqual(typeof _cache !== "undefined", true, "Expected not undefined.");
			assert.strictEqual(_cache.key, "property-key-one", "Expected 'property-key-one'.");
			assert.strictEqual(instanceOfCelastrinaType(CacheProperty, _cache.cache), true, "Expected 'property-key-one'.");
			assert.strictEqual(_cache.cache.time, 2, "Expected 2.");
			assert.strictEqual(_cache.cache.unit, "seconds", "Expected 'seconds'.");
		});
		it("should create using ttl.", async () => {
			let _CacheProperty = {_content: {type: "application/vnd.celastrinajs.attribute+json;CacheProperty"},
				key: "property-key-one",
				ttl: 2};
			let _parser = new CachePropertyParser();
			let _cache = await _parser._create(_CacheProperty);
			assert.strictEqual(_cache != null, true, "Expected no null.");
			assert.strictEqual(typeof _cache !== "undefined", true, "Expected not undefined.");
			assert.strictEqual(_cache.key, "property-key-one", "Expected 'property-key-one'.");
			assert.strictEqual(instanceOfCelastrinaType(CacheProperty, _cache.cache), true, "Expected 'property-key-one'.");
			assert.strictEqual(_cache.cache.time, 2, "Expected 2.");
			assert.strictEqual(_cache.cache.unit, "minutes", "Expected 'minutes'.");
		});
		it("should create using unit.", async () => {
			let _CacheProperty = {_content: {type: "application/vnd.celastrinajs.attribute+json;CacheProperty"},
				key: "property-key-one",
				unit: "seconds"};
			let _parser = new CachePropertyParser();
			let _cache = await _parser._create(_CacheProperty);
			assert.strictEqual(_cache != null, true, "Expected no null.");
			assert.strictEqual(typeof _cache !== "undefined", true, "Expected not undefined.");
			assert.strictEqual(_cache.key, "property-key-one", "Expected 'property-key-one'.");
			assert.strictEqual(instanceOfCelastrinaType(CacheProperty, _cache.cache), true, "Expected 'property-key-one'.");
			assert.strictEqual(_cache.cache.time, 5, "Expected 2.");
			assert.strictEqual(_cache.cache.unit, "seconds", "Expected 'seconds'.");
		});
		it("should create noCache.", async () => {
			let _CacheProperty = {_content: {type: "application/vnd.celastrinajs.attribute+json;CacheProperty"},
				key: "property-key-one",
				noCache: true};
			let _parser = new CachePropertyParser();
			let _cache = await _parser._create(_CacheProperty);
			assert.strictEqual(_cache != null, true, "Expected no null.");
			assert.strictEqual(typeof _cache !== "undefined", true, "Expected not undefined.");
			assert.strictEqual(_cache.key, "property-key-one", "Expected 'property-key-one'.");
			assert.strictEqual(instanceOfCelastrinaType(CacheProperty, _cache.cache), true, "Expected 'property-key-one'.");
			assert.strictEqual(_cache.cache.cache, false, "Expected false.");
			assert.strictEqual(_cache.cache.lastUpdated, null, "Expected null.");
		});
		it("should create noExpire.", async () => {
			let _CacheProperty = {_content: {type: "application/vnd.celastrinajs.attribute+json;CacheProperty"},
				key: "property-key-one",
				noExpire: true};
			let _parser = new CachePropertyParser();
			let _cache = await _parser._create(_CacheProperty);
			assert.strictEqual(_cache != null, true, "Expected no null.");
			assert.strictEqual(typeof _cache !== "undefined", true, "Expected not undefined.");
			assert.strictEqual(_cache.key, "property-key-one", "Expected 'property-key-one'.");
			assert.strictEqual(instanceOfCelastrinaType(CacheProperty, _cache.cache), true, "Expected 'property-key-one'.");
			assert.strictEqual(_cache.cache.cache, true, "Expected false.");
			assert.strictEqual(_cache.cache.lastUpdated, null, "Expected null.");
			assert.strictEqual(_cache.cache.time, 0, "Expected 0.");
		});
		it("should prioritize noCache over noExpire.", async () => {
			let _CacheProperty = {_content: {type: "application/vnd.celastrinajs.attribute+json;CacheProperty"},
				key: "property-key-one",
				noExpire: true,
				noCache: true};
			let _parser = new CachePropertyParser();
			let _cache = await _parser._create(_CacheProperty);
			assert.strictEqual(_cache != null, true, "Expected no null.");
			assert.strictEqual(typeof _cache !== "undefined", true, "Expected not undefined.");
			assert.strictEqual(_cache.key, "property-key-one", "Expected 'property-key-one'.");
			assert.strictEqual(instanceOfCelastrinaType(CacheProperty, _cache.cache), true, "Expected 'property-key-one'.");
			assert.strictEqual(_cache.cache.cache, false, "Expected false.");
			assert.strictEqual(_cache.cache.lastUpdated, null, "Expected null.");
		});
	});
});
