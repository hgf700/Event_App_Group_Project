import { Component, signal } from '@angular/core';
// import { RouterOutlet } from '@angular/router';
import {Layout} from '../Core/layout/layout'

@Component({
  selector: 'app-root',
  imports: [Layout],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App {
  protected readonly title = signal('Frontend');
}
