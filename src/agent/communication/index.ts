// Types and interfaces
export * from './types';

// Core communication components
export { MessageProtocol } from './message-protocol';
export { MessageHandlerRegistry } from './message-handler';
export { CommunicationManager } from './communication-manager';

// Communication channels
export { DirectChannel } from './channels/direct-channel';
export { WebSocketChannel } from './channels/websocket-channel';

// Utility functions for creating common messages
export { MessageFactory } from './message-factory';