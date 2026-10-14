import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ServerError } from './server-error';

describe('ServerError', () => {
  let component: ServerError;
  let fixture: ComponentFixture<ServerError>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ServerError],
    }).compileComponents();

    fixture = TestBed.createComponent(ServerError);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
