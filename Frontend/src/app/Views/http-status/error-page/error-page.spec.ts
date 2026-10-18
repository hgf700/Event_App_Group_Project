
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ErrorPage, ErrorPageConfig } from './error-page';

describe('ErrorPage', () => {
  let component: ErrorPage;
  let fixture: ComponentFixture<ErrorPage>;

  const mockConfig: ErrorPageConfig = {
    code: '404',
    title: 'Page not found',
    message: 'The page you are looking for does not exist.',
    primaryLabel: 'Go home',
    primaryRoute: '/',
  };

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ErrorPage],
    }).compileComponents();

    fixture = TestBed.createComponent(ErrorPage);
    component = fixture.componentInstance;

    fixture.componentRef.setInput('config', mockConfig);

    fixture.detectChanges();
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should display the configured error information', () => {
    const element: HTMLElement = fixture.nativeElement;

    expect(element.querySelector('.error-code')?.textContent?.trim())
      .toBe('404');

    expect(element.querySelector('h1')?.textContent?.trim())
      .toBe('Page not found');

    expect(element.querySelector('.message')?.textContent?.trim())
      .toBe('The page you are looking for does not exist.');
  });
});
