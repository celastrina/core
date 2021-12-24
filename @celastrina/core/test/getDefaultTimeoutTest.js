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
const {getDefaultTimeout} = require("../Core");
const assert = require("assert");

describe("getDefaultTimeout", () => {
	it("should return DEFAULT_TIMEOUT", () => {
		assert.strictEqual(getDefaultTimeout(), 5000, "Expected 5000.");
	});
	it("should return argument _default_", () => {
		assert.strictEqual(getDefaultTimeout(6000), 6000, "Expected 6000.");
	});
	it("should return system override, no argument", () => {
		process.env["celastrinajs.core.service.timeout.default"] = "7000";
		assert.strictEqual(getDefaultTimeout(), 7000, "Expected 7000.");
		delete process.env["celastrinajs.core.service.timeout.default"];
	});
	it("should return system override, with argument", () => {
		process.env["celastrinajs.core.service.timeout.default"] = "7000";
		assert.strictEqual(getDefaultTimeout(3000), 7000, "Expected 7000.");
		delete process.env["celastrinajs.core.service.timeout.default"];
	});
});
