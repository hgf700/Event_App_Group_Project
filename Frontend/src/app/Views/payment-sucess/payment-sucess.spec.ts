import { ComponentFixture, TestBed } from '@angular/core/testing';

import { PaymentSucess } from './payment-sucess';

describe('PaymentSucess', () => {
  let component: PaymentSucess;
  let fixture: ComponentFixture<PaymentSucess>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [PaymentSucess],
    }).compileComponents();

    fixture = TestBed.createComponent(PaymentSucess);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
