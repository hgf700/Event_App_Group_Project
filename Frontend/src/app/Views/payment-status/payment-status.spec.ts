import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { PaymentStatus } from './payment-status';

describe('PaymentSuccess', () => {
  let component: PaymentStatus;
  let fixture: ComponentFixture<PaymentStatus>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [PaymentStatus],
      providers: [provideRouter([])],
    }).compileComponents();

    fixture = TestBed.createComponent(PaymentStatus);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
