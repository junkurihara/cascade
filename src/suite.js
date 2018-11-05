/**
 * suite.js
 */

export class Suite {
  constructor() {
    if (new.target === Suite) {
      throw new TypeError('SuiteClassCannotBeInstantiatedDirectly');
    }
    if (
      this.constructor.generateKey === undefined ||
      this.constructor.encrypt === undefined ||
      this.constructor.decrypt === undefined ||
      this.constructor.sign === undefined ||
      this.constructor.verify === undefined ||
      this.constructor.importKey === undefined
    ) {
      throw new TypeError('MustOverrideAllMethods');
    }
  }
}