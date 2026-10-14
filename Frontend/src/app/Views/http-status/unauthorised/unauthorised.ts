import { Component } from '@angular/core';
import { ErrorPage, ErrorPageConfig } from '../error-page/error-page';

@Component({
  selector: 'app-unauthorised',
  standalone: true,
  imports: [ErrorPage],
  template: `
    <app-error-page [config]="config" />
  `,
  templateUrl: './unauthorised.html',
  styleUrl: './unauthorised.css',
})
export class Unauthorised {

  config: ErrorPageConfig = {
    code: '401',
    title: 'Zaloguj się',
    message:
      'Twoja sesja wygasła lub nie jesteś zalogowany. Zaloguj się, aby kontynuować.',
    primaryLabel: 'Przejdź do logowania',
    primaryRoute: '/login',
    secondaryLabel: 'Strona główna',
    secondaryRoute: '/',
  };
}
