import { bootstrapApplication } from '@angular/platform-browser';
import { appConfig } from './app/base/app.config';
import { App } from './app/base/app';

bootstrapApplication(App, appConfig).catch((err) => console.error(err));
