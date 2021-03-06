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
const {CelastrinaError, LOG_LEVEL, Configuration, Sentry, Subject, Context} = require("../Core");
const {MockAzureFunctionContext} = require("./AzureFunctionContextMock");
const {MockResourceAuthorization} = require("./ResourceAuthorizationTest");
const {MockPropertyManager} = require("./PropertyManagerTest");
const assert = require("assert");

class MockContext extends Context {
    constructor(config) {
        super(config);
    }
    setMonitorMode() {this._monitor = true;}
}

describe("BaseContext", () => {
    describe("#constructor(azcontext, config)", () => {
        it("sets azcontext and config", async () => {
            let _config = new Configuration("mock_configuration");
            let _azcontext = new MockAzureFunctionContext();
            await _config.initialize(_azcontext);
            let _context = new Context(_config);
            assert.strictEqual(_context._config, _config);
            assert.strictEqual(typeof _context._requestId, "string");
            assert.strictEqual(_context._monitor, false);
            assert.strictEqual(_context._action, "process");
        });
    });
    describe("#get name()",  () => {
        it("Has name 'mock_configuration'", async () => {
            let _config = new Configuration("mock_configuration");
            let _azcontext = new MockAzureFunctionContext();
            await _config.initialize(_azcontext);
            let _context = new Context(_config);
            assert.strictEqual(_context.name, "mock_configuration");
        });
    });
    describe("#get config()",  () => {
        it("Has config", async () => {
            let _config = new Configuration("mock_configuration");
            let _azcontext = new MockAzureFunctionContext();
            await _config.initialize(_azcontext);
            let _context = new Context(_config);
            assert.strictEqual(_context.config, _config);
        });
    });
    describe("#get action()", () => {
        it("Has action 'process'", async () => {
            let _config = new Configuration("mock_configuration");
            let _azcontext = new MockAzureFunctionContext();
            await _config.initialize(_azcontext);
            let _context = new Context(_config);
            assert.strictEqual(_context.action, "process");
        });
    });
    describe("#get azureFunctionContext()", () => {
        it("Has azureFunctionContext.", async () => {
            let _config = new Configuration("mock_configuration");
            let _azcontext = new MockAzureFunctionContext();
            await _config.initialize(_azcontext);
            let _context = new Context( _config);
            assert.strictEqual(_context.azureFunctionContext, _azcontext);
        });
    });
    describe("logging", () => {
        describe("#log(message, level = LOG_LEVEL.INFO, subject = null)", () => {
            it("Default logs to info", async () => {
                let _config = new Configuration("mock_configuration");
                let _azcontext = new MockAzureFunctionContext();
                await _config.initialize(_azcontext);
                let _context = new Context( _config);
                await _context.initialize();
                _azcontext.log.reset();
                _context.log("mock_message");

                //[mock_function][mock_configuration][mock_invocation_id][ff99105a-f3b5-40a1-b0a5-c4a1b2b00cbd][mock_trace_id]: mock_message

                assert.strictEqual(_azcontext.log.message, "[mock_function][mock_configuration][mock_invocation_id][" + _context.requestId + "][mock_trace_id]: mock_message");
                assert.strictEqual(_azcontext.log.invoked, "info");
            });
            it("Logs WARN", async () => {
                let _config = new Configuration("mock_configuration");
                let _azcontext = new MockAzureFunctionContext();
                await _config.initialize(_azcontext);
                let _context = new Context( _config);
                await _context.initialize();
                _azcontext.log.reset();
                _context.log("mock_message", LOG_LEVEL.WARN);
                assert.strictEqual(_azcontext.log.message, "[mock_function][mock_configuration][mock_invocation_id][" + _context.requestId + "][mock_trace_id]: mock_message");
                assert.strictEqual(_azcontext.log.invoked, "warn");
            });
            it("Logs ERROR", async () => {
                let _config = new Configuration("mock_configuration");
                let _azcontext = new MockAzureFunctionContext();
                await _config.initialize(_azcontext);
                let _context = new Context( _config);
                await _context.initialize();
                _azcontext.log.reset();
                _context.log("mock_message", LOG_LEVEL.ERROR);
                assert.strictEqual(_azcontext.log.message, "[mock_function][mock_configuration][mock_invocation_id][" + _context.requestId + "][mock_trace_id]: mock_message");
                assert.strictEqual(_azcontext.log.invoked, "error");
            });
            it("Logs VERBOSE", async () => {
                let _config = new Configuration("mock_configuration");
                let _azcontext = new MockAzureFunctionContext();
                await _config.initialize(_azcontext);
                let _context = new Context( _config);
                await _context.initialize();
                _azcontext.log.reset();
                _context.log("mock_message", LOG_LEVEL.VERBOSE);
                assert.strictEqual(_azcontext.log.message, "[mock_function][mock_configuration][mock_invocation_id][" + _context.requestId + "][mock_trace_id]: mock_message");
                assert.strictEqual(_azcontext.log.invoked, "verbose");
            });
            it("Logs WARN from THREAT with THREAT tagging", async () => {
                let _config = new Configuration("mock_configuration");
                let _azcontext = new MockAzureFunctionContext();
                await _config.initialize(_azcontext);
                let _context = new Context( _config);
                await _context.initialize();
                _azcontext.log.reset();
                _context.log("mock_message", LOG_LEVEL.THREAT);
                assert.strictEqual(_azcontext.log.message, "[mock_function][mock_configuration][mock_invocation_id][" + _context.requestId + "][mock_trace_id][THREAT]: mock_message");
                assert.strictEqual(_azcontext.log.invoked, "warn");
            });
            it("Logs VERBOSE from unknown", async () => {
                let _config = new Configuration("mock_configuration");
                let _azcontext = new MockAzureFunctionContext();
                await _config.initialize(_azcontext);
                let _context = new Context( _config);
                await _context.initialize();
                _azcontext.log.reset();
                let __LEVEL = LOG_LEVEL;
                __LEVEL.UNKNOWN = 99;
                _context.log("mock_message", __LEVEL.UNKNOWN);
                assert.strictEqual(_azcontext.log.message, "[mock_function][mock_configuration][mock_invocation_id][" + _context.requestId + "][mock_trace_id]: mock_message");
                assert.strictEqual(_azcontext.log.invoked, "verbose");
            });
            it("Logs INFO with Subject 'mock_subject'", async () => {
                let _config = new Configuration("mock_configuration");
                let _azcontext = new MockAzureFunctionContext();
                await _config.initialize(_azcontext);
                let _context = new Context( _config);
                await _context.initialize();
                _azcontext.log.reset();
                _context.log("mock_message", LOG_LEVEL.INFO, "mock_subject");
                assert.strictEqual(_azcontext.log.message, "[mock_function][mock_configuration][mock_invocation_id][" + _context.requestId + "][mock_trace_id][mock_subject]: mock_message");
                assert.strictEqual(_azcontext.log.invoked, "info");
            });
        });
        describe("#logObjectAsJSON(object, level = LOG_LEVEL.INFO, subject = null)", () => {
            it("Stringifys object and forwards LEVEL and Subject", async () => {
                let _config = new Configuration("mock_configuration");
                let _azcontext = new MockAzureFunctionContext();
                await _config.initialize(_azcontext);
                let _context = new Context( _config);
                await _context.initialize();
                _azcontext.log.reset();
                let _obj = {mock: "value"};
                _context.logObjectAsJSON(_obj, LOG_LEVEL.INFO, "mock_subject");
                assert.strictEqual(_azcontext.log.message, "[mock_function][mock_configuration][mock_invocation_id][" + _context.requestId + "][mock_trace_id][mock_subject]: {\"mock\":\"value\"}");
                assert.strictEqual(_azcontext.log.invoked, "info");
            });
        });
    });
    describe("subject", () => {
        it("Sets subject passed in", async () => {
            let _config = new Configuration("mock_configuration");
            let _azcontext = new MockAzureFunctionContext();
            await _config.initialize(_azcontext);
            let _context = new Context(_config);
            await _context.initialize();
            let _subject = new Subject("mock_subject");
            _context.subject = _subject;
            assert.strictEqual(_context.subject, _subject);
        });
    });
    describe("properties", () => {
        describe("#get properties()", () => {
            it("Has properties from configuration", async () => {
                let _config = new Configuration("mock_configuration");
                let _azcontext = new MockAzureFunctionContext();
                await _config.initialize(_azcontext);
                let _context = new Context(_config);
                let _pm = new MockPropertyManager();
                _config.setValue(Configuration.CONFIG_PROPERTY, _pm);
                assert.strictEqual(_context.properties, _pm);
            });
        });
        describe("#getProperty(key, defaultValue)", () => {
            it("shoudl get a property", async () => {
                let _config = new Configuration("mock_configuration");
                let _azcontext = new MockAzureFunctionContext();
                let _pm = new MockPropertyManager();
                _pm.mockProperty("mock_string_key", "value_1");
                _config.setValue(Configuration.CONFIG_PROPERTY, _pm);
                await _config.initialize(_azcontext);
                let _context = new Context(_config);
                await _context.initialize();
                assert.strictEqual(await _context.getProperty("mock_string_key"), "value_1", "Expected 'value_1'.");
            });
        });
    });
    describe("bindings", () => {
        describe("#setBinding(name, value = null)", () => {
            it("Sets binding by name using default value null", async () => {
                let _config = new Configuration("mock_configuration");
                let _azcontext = new MockAzureFunctionContext();
                await _config.initialize(_azcontext);
                let _context = new Context(_config);
                await _context.initialize();
                await _context.setBinding("mock_bindning-one");
                assert.strictEqual(_azcontext.bindings["mock_bindning-one"], null);
            });
            it("Sets binding by name", async () => {
                let _config = new Configuration("mock_configuration");
                let _azcontext = new MockAzureFunctionContext();
                await _config.initialize(_azcontext);
                let _context = new Context(_config);
                await _context.initialize();
                await _context.setBinding("mock_bindning-one", 42);
                assert.strictEqual(_azcontext.bindings["mock_bindning-one"], 42);
            });
        });
        describe("#getBinding(name, defaultValue = null)", () => {
            it("Gets binding set by Azure Function", async () => {
                let _config = new Configuration("mock_configuration");
                let _azcontext = new MockAzureFunctionContext();
                await _config.initialize(_azcontext);
                let _context = new Context(_config);
                await _context.initialize();
                assert.deepStrictEqual(await _context.getBinding("mockBindingTwo"), {key: "mock_key", value: "mock_value"});
            });
            it("Gets binding set by setter", async () => {
                let _config = new Configuration("mock_configuration");
                let _azcontext = new MockAzureFunctionContext();
                _azcontext.bindings["mock_bindning-one"] = 42;
                await _config.initialize(_azcontext);
                let _context = new Context(_config);
                assert.deepStrictEqual(await _context.getBinding("mock_bindning-one"), 42);
            });
            it("Returns binding if null or not defined", async () => {
                let _config = new Configuration("mock_configuration");
                let _azcontext = new MockAzureFunctionContext();
                await _config.initialize(_azcontext);
                let _context = new Context(_config);
                await _context.initialize();
                assert.deepStrictEqual(await _context.getBinding("mock_bindning-two", 42), 42);
            });
        });
        describe("#initialize()", () => {
            describe("Initializing trace ID if present.", () => {
                it("has trace ID", async () => {
                    let _config = new Configuration("mock_configuration");
                    let _azcontext = new MockAzureFunctionContext();
                    await _config.initialize(_azcontext);
                    let _context = new Context(_config);
                    await _context.initialize();
                    assert.strictEqual(_context.traceId, _azcontext.traceContext.traceparent);
                });
            });
            describe("Initializing in monitor mode..", () => {
                it("Monitor is true and response not null.", async () => {
                    let _config = new Configuration("mock_configuration");
                    let _azcontext = new MockAzureFunctionContext();
                    await _config.initialize(_azcontext);
                    let _context = new Context(_config);
                    _context._monitor = true;
                    await _context.initialize();
                    assert.strictEqual(_context.isMonitorInvocation, true);
                    assert.notStrictEqual(_context.monitorResponse, null);
                });
            });
        });
    });
});

module.exports = {
    MockContext: MockContext
};
