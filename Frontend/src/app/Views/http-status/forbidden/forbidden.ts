import { Component } from '@angular/core';
import { ErrorPage, ErrorPageConfig } from '../error-page/error-page';

@Component({
  selector: 'app-forbidden',
  standalone: true,
  imports: [ErrorPage],
  template: ` <app-error-page [config]="config" /> `,
  templateUrl: './forbidden.html',
  styleUrl: './forbidden.css',
})
export class Forbidden {
  config: ErrorPageConfig = {
    code: '403',
    title: 'Brak uprawnień',
    message:
      'Nie masz uprawnień do wyświetlenia tej strony. Jeśli uważasz, że to błąd, skontaktuj się z administratorem.',
    primaryLabel: 'Wróć do strony głównej',
    primaryRoute: '/',
  };
}
