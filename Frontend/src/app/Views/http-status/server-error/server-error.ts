import { Component } from '@angular/core';
import { ErrorPage, ErrorPageConfig } from '../error-page/error-page';

@Component({
  selector: 'app-server-error',
  standalone: true,
  imports: [ErrorPage],
  template: ` <app-error-page [config]="config" /> `,
  templateUrl: './server-error.html',
  styleUrl: './server-error.css',
})
export class ServerError {
  config: ErrorPageConfig = {
    code: '500',
    title: 'Coś poszło nie tak',
    message: 'Wystąpił nieoczekiwany błąd. Spróbuj ponownie za chwilę.',
    primaryLabel: 'Strona główna',
    primaryRoute: '/',
  };
}
