import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';

import { EditUserEmail } from './edit-user-email';

describe('EditUserEmail', () => {
  let component: EditUserEmail;
  let fixture: ComponentFixture<EditUserEmail>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [EditUserEmail],
      providers: [provideRouter([])]
    }).compileComponents();

    fixture = TestBed.createComponent(EditUserEmail);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
