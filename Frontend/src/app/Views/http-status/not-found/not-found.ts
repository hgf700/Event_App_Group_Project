import { Component } from '@angular/core';
import { ErrorPage, ErrorPageConfig } from '../error-page/error-page';

@Component({
  selector: 'app-not-found',
  standalone: true,
  imports: [ErrorPage],
  template: ` <app-error-page [config]="config" /> `,
  templateUrl: './not-found.html',
  styleUrl: './not-found.css',
})
export class NotFound {
  config: ErrorPageConfig = {
    code: '404',
    title: 'Nie znaleziono strony',
    message: 'Strona, której szukasz, nie istnieje. Sprawdź adres lub wróć do wydarzeń.',
    primaryLabel: 'Strona główna',
    primaryRoute: '/',
  };
}
