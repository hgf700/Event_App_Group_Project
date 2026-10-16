import { Component, signal } from '@angular/core';
import { Layout } from '../Views/shared/layout/layout';
// import { RouterOutlet } from '@angular/router';

@Component({
  selector: 'app-root',
  imports: [Layout],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App {
  protected readonly title = signal('EventApp');
}
