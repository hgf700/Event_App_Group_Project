import { CommonModule } from '@angular/common';
import { Component, inject, Input } from '@angular/core';
import { Router } from '@angular/router';

@Component({
  selector: 'app-error-page',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './error-page.html',
  styleUrl: './error-page.css',
})
export class ErrorPage {
  @Input({ required: true }) config!: ErrorPageConfig;

  private router = inject(Router);

  navigate(route: string): void {
    void this.router.navigateByUrl(route);
  }
}

export interface ErrorPageConfig {
  code: string;
  title: string;
  message: string;
  primaryLabel: string;
  primaryRoute: string;
  secondaryLabel?: string;
  secondaryRoute?: string;
}
