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
const {Configuration, AddOnEventHandler, AddOnEvent, AddOnManager, instanceOfCelastrinaType, CelastrinaEvent} = require("../Core");
const {MockAzureFunctionContext} = require("./AzureFunctionContextMock");
const assert = require("assert");
const {MockAddOn} = require("./ConfigurationTest");
const {MockContext} = require("./ContextTest");

class AddOnMockOne extends MockAddOn {
	/**@type{Object}*/static get $object() {return {addOn: "AddOnMockOne"}};
	constructor() {
		super();
		this.invokedHandler = false;
		this.rejectEvents = false;
	}
	/**
	 * @param azcontext
	 * @param config
	 * @param {AddOnEventHandler} handler
	 * @return {Promise<void>}
	 */
	async install(azcontext, config, handler) {
		await super.install(azcontext, config, handler);
		await handler.addEventListener(AddOnEvent.TYPE.INITIALIZE, this, AddOnMockOne.handler);
	}
	set reject(reject) {this.rejectEvents = reject;}
	static async handler(a, b, c) {
		b.invokedHandler = true;
		if(b.rejectEvents) a.reject();
	}
}
class AddOnMockTwo extends MockAddOn {
	/**@type{Object}*/static get $object() {return {addOn: "AddOnMockTwo"}};
	constructor() {
		super([AddOnMockOne.$object.addOn]);
		this.iniitalizeInvoked = false;
		this.authenticateInvoked = false;
		this.authorizeInvoked = false;
		this.beforeValidateInvoked = false;
		this.beforeLoadInvoked = false;
		this.beforeMonitorInvoked = false;
		this.beforeProcessInvoked = false;
		this.beforeSaveInvoked = false;
		this.beforeExceptionInvoked = false;
		this.beforeTerminateInvoked = false;
		this.afterValidateInvoked = false;
		this.afterLoadInvoked = false;
		this.afterMonitorInvoked = false;
		this.afterProcessInvoked = false;
		this.afterSaveInvoked = false;
		this.afterExceptionInvoked = false;
		this.afterTerminateInvoked = false;
	}
	reset() {
		this.iniitalizeInvoked = false;
		this.authenticateInvoked = false;
		this.authorizeInvoked = false;
		this.beforeValidateInvoked = false;
		this.beforeLoadInvoked = false;
		this.beforeMonitorInvoked = false;
		this.beforeProcessInvoked = false;
		this.beforeSaveInvoked = false;
		this.beforeExceptionInvoked = false;
		this.beforeTerminateInvoked = false;
		this.afterValidateInvoked = false;
		this.afterLoadInvoked = false;
		this.afterMonitorInvoked = false;
		this.afterProcessInvoked = false;
		this.afterSaveInvoked = false;
		this.afterExceptionInvoked = false;
		this.afterTerminateInvoked = false;
	}
	/**
	 * @param azcontext
	 * @param config
	 * @param {AddOnEventHandler} handler
	 * @return {Promise<void>}
	 */
	async install(azcontext, config, handler) {
		await super.install(azcontext, config, handler);
		await handler.addEventListener(AddOnEvent.TYPE.INITIALIZE, this, AddOnMockTwo.initialize);
		await handler.addEventListener(AddOnEvent.TYPE.AUTHENTICATE, this, AddOnMockTwo.authenticate);
		await handler.addEventListener(AddOnEvent.TYPE.AUTHORIZE, this, AddOnMockTwo.authorize);
		await handler.addEventListener(AddOnEvent.TYPE.BEFORE_VALIDATE, this, AddOnMockTwo.beforeValidate);
		await handler.addEventListener(AddOnEvent.TYPE.AFTER_VALIDATE, this, AddOnMockTwo.afterValidate);
		await handler.addEventListener(AddOnEvent.TYPE.BEFORE_LOAD, this, AddOnMockTwo.beforeLoad);
		await handler.addEventListener(AddOnEvent.TYPE.AFTER_LOAD, this, AddOnMockTwo.afterLoad);
		await handler.addEventListener(AddOnEvent.TYPE.BEFORE_MONITOR, this, AddOnMockTwo.beforeMonitor);
		await handler.addEventListener(AddOnEvent.TYPE.AFTER_MONITOR, this, AddOnMockTwo.afterMonitor);
		await handler.addEventListener(AddOnEvent.TYPE.BEFORE_PROCESS, this, AddOnMockTwo.beforeProcess);
		await handler.addEventListener(AddOnEvent.TYPE.AFTER_PROCESS, this, AddOnMockTwo.afterProcess);
		await handler.addEventListener(AddOnEvent.TYPE.BEFORE_SAVE, this, AddOnMockTwo.beforeSave);
		await handler.addEventListener(AddOnEvent.TYPE.AFTER_SAVE, this, AddOnMockTwo.afterSave);
		await handler.addEventListener(AddOnEvent.TYPE.BEFORE_EXCEPTION, this, AddOnMockTwo.beforeException);
		await handler.addEventListener(AddOnEvent.TYPE.AFTER_EXCEPTION, this, AddOnMockTwo.afterException);
		await handler.addEventListener(AddOnEvent.TYPE.BEFORE_TERMINATE, this, AddOnMockTwo.beforeTerminate);
		await handler.addEventListener(AddOnEvent.TYPE.AFTER_TERMINATE, this, AddOnMockTwo.afterTerminate);
	}
	static async initialize(event, addon) {
		addon.iniitalizeInvoked = true;
	}
	static async authenticate(event, addon) {
		addon.authenticateInvoked = true;
	}
	static async authorize(event, addon) {
		addon.authorizeInvoked = true;
	}
	static async beforeValidate(event, addon) {
		addon.beforeValidateInvoked = true;
	}
	static async afterValidate(event, addon) {
		addon.afterValidateInvoked = true;
	}
	static async beforeLoad(event, addon) {
		addon.beforeLoadInvoked = true;
	}
	static async afterLoad(event, addon) {
		addon.afterLoadInvoked = true;
	}
	static async beforeMonitor(event, addon) {
		addon.beforeMonitorInvoked = true;
	}
	static async afterMonitor(event, addon) {
		addon.afterMonitorInvoked = true;
	}
	static async beforeProcess(event, addon) {
		addon.beforeProcessInvoked = true;
	}
	static async afterProcess(event, addon) {
		addon.afterProcessInvoked = true;
	}
	static async beforeSave(event, addon) {
		addon.beforeSaveInvoked = true;
	}
	static async afterSave(event, addon) {
		addon.afterSaveInvoked = true;
	}
	static async beforeException(event, addon) {
		addon.beforeExceptionInvoked = true;
	}
	static async afterException(event, addon) {
		addon.afterExceptionInvoked = true;
	}
	static async beforeTerminate(event, addon) {
		addon.beforeTerminateInvoked = true;
	}
	static async afterTerminate(event, addon) {
		addon.afterTerminateInvoked = true;
	}
}
class AddOnMockThree extends MockAddOn {
	/**@type{Object}*/static get $object() {return {addOn: "AddOnMockThree"}};
	constructor() {
		super([AddOnMockOne.$object.addOn]);
		this.eventRejected = false;
	}
	/**
	 * @param azcontext
	 * @param config
	 * @param {AddOnEventHandler} handler
	 * @return {Promise<void>}
	 */
	async install(azcontext, config, handler) {
		await super.install(azcontext, config, handler);
		await handler.addEventListener(AddOnEvent.TYPE.INITIALIZE, this, AddOnMockThree.handler);
	}

	static async handler(a, b, c) {
		b.eventRejected = a.isRejected;
	}
}
class AddOnMockFour extends MockAddOn {
	/**@type{Object}*/static get $object() {return {addOn: "AddOnMockFour"}};
	constructor() {
		super([AddOnMockOne.$object.addOn, AddOnMockThree.$object.addOn]);
	}
}
describe("AddOnEvent", () => {
	describe("types", () => {
		it("is celastrina type", () => {
			let _event = new AddOnEvent("mock_type", null);
			assert.strictEqual(instanceOfCelastrinaType(CelastrinaEvent, _event), true, "Expected true.");
			assert.strictEqual(instanceOfCelastrinaType(AddOnEvent, _event), true, "Expected true.");
		});
		it("has precanned types", () => {
			assert.strictEqual(AddOnEvent.TYPE.INITIALIZE, "onInitialize", "Expected 'onInitialize'.");
			assert.strictEqual(AddOnEvent.TYPE.AUTHENTICATE, "onAuthenticate", "Expected 'onAuthenticate'.");
			assert.strictEqual(AddOnEvent.TYPE.AUTHORIZE, "onAuthorize", "Expected 'onAuthorize'.");
			assert.strictEqual(AddOnEvent.TYPE.BEFORE_VALIDATE, "onBeforeValidate", "Expected 'onBeforeValidate'.");
			assert.strictEqual(AddOnEvent.TYPE.AFTER_VALIDATE, "onAfterValidate", "Expected 'onAfterValidate'.");
			assert.strictEqual(AddOnEvent.TYPE.BEFORE_LOAD, "onBeforeLoad", "Expected 'onBeforeLoad'.");
			assert.strictEqual(AddOnEvent.TYPE.AFTER_LOAD, "onAfterLoad", "Expected 'onAfterLoad'.");
			assert.strictEqual(AddOnEvent.TYPE.BEFORE_MONITOR, "onBeforeMonitor", "Expected 'onBeforeMonitor'.");
			assert.strictEqual(AddOnEvent.TYPE.AFTER_MONITOR, "onAfterMonitor", "Expected 'onAfterMonitor'.");
			assert.strictEqual(AddOnEvent.TYPE.BEFORE_PROCESS, "onBeforeProcess", "Expected 'onBeforeProcess'.");
			assert.strictEqual(AddOnEvent.TYPE.AFTER_PROCESS, "onAfterProcess", "Expected 'onAfterProcess'.");
			assert.strictEqual(AddOnEvent.TYPE.BEFORE_SAVE, "onBeforeSave", "Expected 'onBeforeSave'.");
			assert.strictEqual(AddOnEvent.TYPE.AFTER_SAVE, "onAfterSave", "Expected 'onAfterSave'.");
			assert.strictEqual(AddOnEvent.TYPE.BEFORE_EXCEPTION, "onBeforeException", "Expected 'onBeforeException'.");
			assert.strictEqual(AddOnEvent.TYPE.AFTER_EXCEPTION, "onAfterException", "Expected 'onAfterException'.");
			assert.strictEqual(AddOnEvent.TYPE.BEFORE_TERMINATE, "onBeforeTerminate", "Expected 'onBeforeTerminate'.");
			assert.strictEqual(AddOnEvent.TYPE.AFTER_TERMINATE, "onAfterTerminate", "Expected 'onAfterTerminate'.");
		});
	});
	describe("#constructor()", () => {
		it("sets type", () => {
			let _event = new AddOnEvent("mock_type", null);
			assert.strictEqual(_event.type, "mock_type", "Expected 'mock_type'.");
		});
	});
	describe("#addRejectedByAddOn(addon)", () => {
		it("should be rejected by addon object", async () => {
			let _event = new AddOnEvent("mock_type", null);
			let _addon = new AddOnMockOne();
			_event.addRejectedByAddOn(_addon);
			assert.strictEqual(await _event.isRejectedByAddOn(AddOnMockOne), true, "Expected true.");
		});
		it("should not be rejected by addon object", async () => {
			let _event = new AddOnEvent("mock_type", null);
			let _addon = new AddOnMockOne();
			_event.addRejectedByAddOn(_addon);
			assert.strictEqual(await _event.isRejectedByAddOn(AddOnMockTwo), false, "Expected true.");
		});
		it("should be rejected by addon string", async () => {
			let _event = new AddOnEvent("mock_type", null);
			let _addon = new AddOnMockOne();
			_event.addRejectedByAddOn(_addon);
			assert.strictEqual(await _event.isRejectedByAddOn(AddOnMockOne.$object.addOn), true, "Expected true.");
		});
		it("should not be rejected by addon string", async () => {
			let _event = new AddOnEvent("mock_type", null);
			let _addon = new AddOnMockOne();
			_event.addRejectedByAddOn(_addon);
			assert.strictEqual(await _event.isRejectedByAddOn(AddOnMockTwo.$object.addOn), false, "Expected true.");
		});
	});
});
describe("AddOnEventHandler", () => {
	describe("constructor() after manager initialize", () => {
		it("should order listeners by dependency", async () => {
			let _azcontext = new MockAzureFunctionContext();
			let _addon = new AddOnMockOne();
			let _addon3 = new AddOnMockThree();
			let _config = new Configuration("AddOnManagerTest");
			_config.addOn(_addon3);
			_config.addOn(_addon);
			await _config.initialize(_azcontext);

			let _listerns = _config.addOns._listeners.get("onInitialize");

			assert.deepStrictEqual(_listerns[0].addOn, _addon, "Expected 'AddOnMockOne' first.");
			assert.deepStrictEqual(_listerns[1].addOn, _addon3, "Expected 'AddOnMockThree' second.");
		});
	});
	describe("#fireAddOnEvent(type, source, context, data)", () => {
		it("should fire event", async () => {
			let _azcontext = new MockAzureFunctionContext();
			let _addon = new AddOnMockOne();
			let _addonb = new AddOnMockThree();
			let _config = new Configuration("AddOnManagerTest");
			_config.addOn(_addonb);
			_config.addOn(_addon);
			await _config.initialize(_azcontext);
			await _config.addOns.fireAddOnEvent(AddOnEvent.TYPE.INITIALIZE, null, null);
			assert.strictEqual(_addon.invokedHandler, true, "Expected true.");
			assert.strictEqual(_addonb.eventRejected, false, "Expected false.");
		});
		it("should fire event and reject", async () => {
			let _azcontext = new MockAzureFunctionContext();
			let _addon = new AddOnMockOne();
			let _addonb = new AddOnMockThree();
			_addon.reject = true;
			let _config = new Configuration("AddOnManagerTest");
			_config.addOn(_addonb);
			_config.addOn(_addon);
			await _config.initialize(_azcontext);
			await _config.addOns.fireAddOnEvent(AddOnEvent.TYPE.INITIALIZE, null, null);
			assert.strictEqual(_addon.invokedHandler, true, "Expected true.");
			assert.strictEqual(_addonb.eventRejected, true, "Expected true.");
		});
	});
});
describe("AddOnManager", () => {
	describe("types", () => {
		it("is celastrina type", () => {
			let _admanager = new AddOnManager();
			assert.strictEqual(instanceOfCelastrinaType(AddOnManager, _admanager), true, "Expected true.");
		});
	});
	describe("#add(addon)", () => {
		it("should resolve addon to target without dependencies immediately", () => {
			let _admanager = new AddOnManager();
			let _addon = new AddOnMockOne();
			_admanager.add(_addon);
			assert.deepStrictEqual(_admanager._target[0], _addon, "Expected _addon.");
		});
		it("should resolve dependent to target", () => {
			let _admanager = new AddOnManager();
			let _addon = new AddOnMockOne();
			let _addon2 = new AddOnMockTwo();
			_admanager.add(_addon);
			_admanager.add(_addon2);
			assert.deepStrictEqual(_admanager._target[0], _addon, "Expected _addon.");
			assert.deepStrictEqual(_admanager._target[1], _addon2, "Expected _addon2.");
		});
		it("should resolve _addon/_addon2, but unresolve _addon3 dependent to target", () => {
			let _admanager = new AddOnManager();
			let _addon = new AddOnMockOne();
			let _addon2 = new AddOnMockTwo();
			let _addon3 = new AddOnMockThree();
			_addon3.mockDependancy("AddOnMockFour");
			_admanager.add(_addon);
			_admanager.add(_addon2);
			_admanager.add(_addon3);
			assert.deepStrictEqual(_admanager._target[0], _addon, "Expected _addon.");
			assert.deepStrictEqual(_admanager._target[1], _addon2, "Expected _addon2.");
			assert.deepStrictEqual(_admanager._unresolved.has("AddOnMockThree"), true, "Expected true.");
		});
	});
	describe("#install(azcontext, parse, cfp, atp)", () => {
		it("should install add-ons.", async () => {
			let _azcontext = new MockAzureFunctionContext();
			let _admanager = new AddOnManager();
			let _addon = new AddOnMockOne();
			let _addon2 = new AddOnMockTwo();
			let _addon3 = new AddOnMockThree();
			let _addon4 = new AddOnMockFour();
			_admanager.add(_addon2);
			_admanager.add(_addon4);
			_admanager.add(_addon3);
			_admanager.add(_addon);
			assert.deepStrictEqual(_admanager._target[0], _addon, "Expected _addon.");
			assert.deepStrictEqual(_admanager._unresolved.has("AddOnMockTwo"), true, "Expected true.");
			assert.deepStrictEqual(_admanager._unresolved.has("AddOnMockThree"), true, "Expected true.");
			assert.deepStrictEqual(_admanager._unresolved.has("AddOnMockFour"), true, "Expected true.");
			await _admanager.install(_azcontext);
			assert.deepStrictEqual(_admanager._target[0], _addon, "Expected _addon.");
			assert.deepStrictEqual(_admanager._target[1], _addon2, "Expected _addon2.");
			assert.deepStrictEqual(_admanager._target[2], _addon3, "Expected _addon3.");
			assert.deepStrictEqual(_admanager._target[3], _addon4, "Expected _addon4.");
		});
		it("should fail install add-ons with four unresolved.", async () => {
			let _azcontext = new MockAzureFunctionContext();
			let _admanager = new AddOnManager();
			let _addon = new AddOnMockOne();
			let _addon2 = new AddOnMockTwo();
			let _addon3 = new AddOnMockThree();
			let _addon4 = new AddOnMockFour();
			_addon4.mockDependancy("FakeDependent");
			_admanager.add(_addon2);
			_admanager.add(_addon4);
			_admanager.add(_addon3);
			_admanager.add(_addon);
			assert.deepStrictEqual(_admanager._target[0], _addon, "Expected _addon.");
			assert.deepStrictEqual(_admanager._unresolved.has("AddOnMockTwo"), true, "Expected true.");
			assert.deepStrictEqual(_admanager._unresolved.has("AddOnMockThree"), true, "Expected true.");
			assert.deepStrictEqual(_admanager._unresolved.has("AddOnMockFour"), true, "Expected true.");
			await assert.rejects(_admanager.install(_azcontext));
		});
		it("should initialize add-ons.", async () => {
			let _azcontext = new MockAzureFunctionContext();
			let _admanager = new AddOnManager();
			let _addon = new AddOnMockOne();
			let _addon2 = new AddOnMockTwo();
			let _addon3 = new AddOnMockThree();
			let _addon4 = new AddOnMockFour();
			_admanager.add(_addon2);
			_admanager.add(_addon4);
			_admanager.add(_addon3);
			_admanager.add(_addon);
			assert.deepStrictEqual(_admanager._target[0], _addon, "Expected _addon.");
			assert.deepStrictEqual(_admanager._unresolved.has("AddOnMockTwo"), true, "Expected true.");
			assert.deepStrictEqual(_admanager._unresolved.has("AddOnMockThree"), true, "Expected true.");
			assert.deepStrictEqual(_admanager._unresolved.has("AddOnMockFour"), true, "Expected true.");
			await _admanager.install(_azcontext);
			assert.deepStrictEqual(_admanager._target[0], _addon, "Expected _addon.");
			assert.deepStrictEqual(_admanager._target[1], _addon2, "Expected _addon2.");
			assert.deepStrictEqual(_admanager._target[2], _addon3, "Expected _addon3.");
			assert.deepStrictEqual(_admanager._target[3], _addon4, "Expected _addon4.");
			await _admanager.initialize(_azcontext, {});
			assert.strictEqual(_addon.invokedInstall, true, "Expected true.");
			assert.strictEqual(_addon2.invokedInstall, true, "Expected true.");
			assert.strictEqual(_addon3.invokedInstall, true, "Expected true.");
			assert.strictEqual(_addon4.invokedInstall, true, "Expected true.");
		});
	});
	describe("Getter and Setter", () => {
		describe("get", () => {
			it("gets after initialize by string", async () => {
				let _azcontext = new MockAzureFunctionContext();
				let _addon = new AddOnMockOne();
				let _config = new Configuration("AddOnManagerTest");
				_config.addOn(_addon);
				await _config.initialize(_azcontext);
				assert.deepStrictEqual(await _config.addOns.get(AddOnMockOne.$object.addOn), _addon, "Expected AddOnMockOne.");
			});
			it("gets after initialize by object", async () => {
				let _azcontext = new MockAzureFunctionContext();
				let _addon = new AddOnMockOne();
				let _config = new Configuration("AddOnManagerTest");
				_config.addOn(_addon);
				await _config.initialize(_azcontext);
				assert.deepStrictEqual(await _config.addOns.get(AddOnMockOne), _addon, "Expected AddOnMockOne.");
			});
		});
	});
	describe("Lifecycles", () => {
		it("should do lifecycle on AddOn2", async () => {
			let _azcontext = new MockAzureFunctionContext();
			let _addon = new AddOnMockOne();
			let _addon2 = new AddOnMockTwo();
			let _config = new Configuration("AddOnManagerTest");
			_config.addOn(_addon);
			_config.addOn(_addon2);
			await _config.initialize(_azcontext);
			let _context = new MockContext(_config);

			await _config.addOns.fireAddOnEvent(AddOnEvent.TYPE.INITIALIZE, null, _context);
			await _config.addOns.fireAddOnEvent(AddOnEvent.TYPE.AUTHENTICATE, null, _context);
			await _config.addOns.fireAddOnEvent(AddOnEvent.TYPE.AUTHORIZE, null, _context);
			await _config.addOns.fireAddOnEvent(AddOnEvent.TYPE.BEFORE_VALIDATE, null, _context);
			await _config.addOns.fireAddOnEvent(AddOnEvent.TYPE.AFTER_VALIDATE, null, _context);
			await _config.addOns.fireAddOnEvent(AddOnEvent.TYPE.BEFORE_LOAD, null, _context);
			await _config.addOns.fireAddOnEvent(AddOnEvent.TYPE.AFTER_LOAD, null, _context);
			await _config.addOns.fireAddOnEvent(AddOnEvent.TYPE.BEFORE_MONITOR, null, _context);
			await _config.addOns.fireAddOnEvent(AddOnEvent.TYPE.AFTER_MONITOR, null, _context);
			await _config.addOns.fireAddOnEvent(AddOnEvent.TYPE.BEFORE_PROCESS, null, _context);
			await _config.addOns.fireAddOnEvent(AddOnEvent.TYPE.AFTER_PROCESS, null, _context);
			await _config.addOns.fireAddOnEvent(AddOnEvent.TYPE.BEFORE_SAVE, null, _context);
			await _config.addOns.fireAddOnEvent(AddOnEvent.TYPE.AFTER_SAVE, null, _context);
			await _config.addOns.fireAddOnEvent(AddOnEvent.TYPE.BEFORE_EXCEPTION, null, _context);
			await _config.addOns.fireAddOnEvent(AddOnEvent.TYPE.AFTER_EXCEPTION, null, _context);
			await _config.addOns.fireAddOnEvent(AddOnEvent.TYPE.BEFORE_TERMINATE, null, _context);
			await _config.addOns.fireAddOnEvent(AddOnEvent.TYPE.AFTER_TERMINATE, null, _context);

			assert.deepStrictEqual(_addon2.iniitalizeInvoked, true, "Expected true.");
			assert.deepStrictEqual(_addon2.authenticateInvoked, true, "Expected true.");
			assert.deepStrictEqual(_addon2.authorizeInvoked, true, "Expected true.");
			assert.deepStrictEqual(_addon2.beforeValidateInvoked, true, "Expected true.");
			assert.deepStrictEqual(_addon2.beforeLoadInvoked, true, "Expected true.");
			assert.deepStrictEqual(_addon2.beforeMonitorInvoked, true, "Expected true.");
			assert.deepStrictEqual(_addon2.beforeProcessInvoked, true, "Expected true.");
			assert.deepStrictEqual(_addon2.beforeSaveInvoked, true, "Expected true.");
			assert.deepStrictEqual(_addon2.beforeExceptionInvoked, true, "Expected true.");
			assert.deepStrictEqual(_addon2.beforeTerminateInvoked, true, "Expected true.");
			assert.deepStrictEqual(_addon2.afterValidateInvoked, true, "Expected true.");
			assert.deepStrictEqual(_addon2.afterLoadInvoked, true, "Expected true.");
			assert.deepStrictEqual(_addon2.afterMonitorInvoked, true, "Expected true.");
			assert.deepStrictEqual(_addon2.afterProcessInvoked, true, "Expected true.");
			assert.deepStrictEqual(_addon2.afterSaveInvoked, true, "Expected true.");
			assert.deepStrictEqual(_addon2.afterExceptionInvoked, true, "Expected true.");
			assert.deepStrictEqual(_addon2.afterTerminateInvoked, true, "Expected true.");
		});
	});
});
