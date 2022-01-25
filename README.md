# celastrina
Celastrina is a JavaScript framework for simplifying server-less compute in Microsoft Azure Functions. Celastrina 
attempts to simplify the configuration and connectivity of common PaaS services in the Azure Platform with a special 
emphasis on security.

Celastrina is flexible enough to support small open-source efforts and can easily scale up to large enterprise 
deployments. Celastrina is committed to maintaining compatibility with JavaScript libraries released by Microsoft and 
will continue to adapt and grow with the Microsoft Azure ecosystem.

@celastrina/core is the core support library for all celastrina add-ons. You can find available add-ons here:

- [@celastrina/http](https://www.npmjs.com/package/@celastrina/http): For use with Azure Function HTTP triggers.
- [@celastrina/timer](https://www.npmjs.com/package/@celastrina/timer): For user with Azure Function Timer triggers.

## Coming Soon
The project team is currently working on add-ons for:
- Google RECAPTCHA.
- Cloud Events, both HTTP and or async triggers from EventGrid or Storage Queue.
- Async Messages from Service Bus or Storage Queue.
- Semaphore and Data Binding

## Documentation
Please visit the github wiki for more information and documentation.
