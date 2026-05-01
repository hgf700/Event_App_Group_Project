import { ComponentFixture, TestBed } from '@angular/core/testing';

import { LoginCallback } from './login-callback';

describe('LoginCallback', () => {
  let component: LoginCallback;
  let fixture: ComponentFixture<LoginCallback>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [LoginCallback],
    }).compileComponents();

    fixture = TestBed.createComponent(LoginCallback);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
