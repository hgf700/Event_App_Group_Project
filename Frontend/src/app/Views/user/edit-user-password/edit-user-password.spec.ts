import { ComponentFixture, TestBed } from '@angular/core/testing';

import { EditUserPassword } from './edit-user-password';

describe('EditUserPassword', () => {
  let component: EditUserPassword;
  let fixture: ComponentFixture<EditUserPassword>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [EditUserPassword],
    }).compileComponents();

    fixture = TestBed.createComponent(EditUserPassword);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
