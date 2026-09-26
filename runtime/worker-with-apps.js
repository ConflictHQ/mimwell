// Opt in with make dev APPS=1 or make deploy APPS=1.
import portal from '../worker.js';
import {withAppBackend} from './worker-app-backend.js';

export default withAppBackend(portal);
