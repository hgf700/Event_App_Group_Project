import { ComponentFixture, TestBed } from '@angular/core/testing';
import { RegisterUser } from './register-user';
import { AuthService } from '../../Services/AuthService';
import { Router, ActivatedRoute } from '@angular/router';
import { of } from 'rxjs';

describe('RegisterUser', () => {
  let component: RegisterUser;
  let fixture: ComponentFixture<RegisterUser>;

  let authServiceMock: any;
  let routerMock: any;

  beforeEach(async () => {
    authServiceMock = {
      registerUserNorm: () => of({ jwt: 'fake-jwt-token' })
    };

    routerMock = {
      navigate: (path: any[]) => {}
    };

    await TestBed.configureTestingModule({
      imports: [RegisterUser],
      providers: [
        { provide: AuthService, useValue: authServiceMock },
        { provide: Router, useValue: routerMock },
        { provide: ActivatedRoute, useValue: { snapshot: { params: {} } } }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(RegisterUser);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should mark submitted true and stop on invalid form', () => {
    component.registerUserForm.setValue({
      email: '',
      password: '',
      confirmPassword: ''
    });

    component.onSubmit();

    expect(component.submitted).toBe(true);
  });

  it.skip('should call API, store jwt and navigate', () => {
    // TODO: mock localStorage.setItem nie propaguje do subscribe callback w vitest env
    let storedKey = '';
    let storedValue = '';

    const originalSetItem = localStorage.setItem;

    localStorage.setItem = (k: string, v: string) => {
      storedKey = k;
      storedValue = v;
    };

    let navigated: any = null;

    routerMock.navigate = (path: any[]) => {
      navigated = path;
    };

    component.registerUserForm.setValue({
      email: 'test@test.pl',
      password: 'Password123!',
      confirmPassword: 'Password123!'
    });

    fixture.detectChanges();

    component.onSubmit();

    expect(storedKey).toBe('jwt');
    expect(storedValue).toBe('fake-jwt-token');
    expect(navigated).toEqual(['/login-callback']);

    localStorage.setItem = originalSetItem;
  });

  it('should set submitted flag', () => {
    component.onSubmit();
    expect(component.submitted).toBe(true);
  });
});
