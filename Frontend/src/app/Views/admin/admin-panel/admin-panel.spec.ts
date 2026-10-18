
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { describe, it, expect, beforeEach, vi } from 'vitest';

import { AdminPanel } from './admin-panel';

describe('AdminPanel', () => {
  let component: AdminPanel;
  let fixture: ComponentFixture<AdminPanel>;
  let router: Router;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AdminPanel],
      providers: [provideRouter([])],
    }).compileComponents();

    router = TestBed.inject(Router);
    vi.spyOn(router, 'navigate').mockResolvedValue(true);

    fixture = TestBed.createComponent(AdminPanel);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should navigate to seed database when seedDatabase is called', () => {
    component.seedDatabase();

    expect(router.navigate).toHaveBeenCalledWith(['/seed-database']);
  });

  it('should navigate to seed database when the button is clicked', () => {
    const button: HTMLButtonElement =
      fixture.nativeElement.querySelector('.seed-database');

    button.click();

    expect(router.navigate).toHaveBeenCalledWith(['/seed-database']);
  });

  it('should display the admin panel title', () => {
    const element: HTMLElement = fixture.nativeElement;

    expect(element.querySelector('h2')?.textContent?.trim())
      .toBe('Panel administracyjny');
  });

  it('should display all navigation links', () => {
    const element: HTMLElement = fixture.nativeElement;
    const links = Array.from(
      element.querySelectorAll('nav a'),
    ).map((link) => link.textContent?.trim());

    expect(links).toContain('Dashboard');
    expect(links).toContain('Wydarzenia');
    expect(links).toContain('Użytkownicy');
    expect(links).toContain('Zablokowani');
    expect(links).toContain('Bilety');
    expect(links).toContain('Zapisane eventy użytkowników');
  });

  it('should display the seed database button', () => {
    const button: HTMLButtonElement =
      fixture.nativeElement.querySelector('.seed-database');

    expect(button).toBeTruthy();
    expect(button.textContent?.trim()).toBe('Seedowanie bazy danych');
  });
});
