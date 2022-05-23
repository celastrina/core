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
const {instanceOfCelastrinaType} = require("../Core");
const assert = require("assert");

class MockTypeA {
    /**@return{Object}*/static get $object() {return {type: "MockTypeA"};}
    constructor() {}
}
class MockTypeB {
    /**@return{Object}*/static get $object() {return {type: "MockTypeB"};}
    constructor() {}
}
class MockTypeC {
    constructor() {}
}

describe("instanceOfCelastringType", () => {
    describe("works correctly!", () => {
        it("should fail type null", () => {
            assert.strictEqual(instanceOfCelastrinaType(null, new MockTypeA()), false, "Expected false.");
        });
        it("should fail source null", () => {
            assert.strictEqual(instanceOfCelastrinaType(MockTypeA, null), false, "Expected false.");
        });
        it("should fail gracefully, both null", () => {
            assert.strictEqual(instanceOfCelastrinaType(null, null), false, "Expected false.");
        });
        it("should fail source not an object, numeric", () => {
            assert.strictEqual(instanceOfCelastrinaType(MockTypeA, 100), false, "Expected false.");
        });
        it("should fail source not an object, string", () => {
            assert.strictEqual(instanceOfCelastrinaType(MockTypeA, "100"), false, "Expected false.");
        });
        it("should fail non-celatrina type", () => {
            assert.strictEqual(instanceOfCelastrinaType(MockTypeA, new MockTypeC()), false, "Expected false.");
        });
        it("should fail celatrina type different", () => {
            assert.strictEqual(instanceOfCelastrinaType(MockTypeA, new MockTypeB()), false, "Expected false.");
        });
        it("should pass celatrina type same", () => {
            assert.strictEqual(instanceOfCelastrinaType(MockTypeA, new MockTypeA()), true, "Expected true.");
        });
    });
});
