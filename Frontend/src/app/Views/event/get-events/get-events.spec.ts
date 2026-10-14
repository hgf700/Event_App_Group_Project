import { ComponentFixture, TestBed } from '@angular/core/testing';

import { GetEvents } from './get-events';

describe('GetEvents', () => {
  let component: GetEvents;
  let fixture: ComponentFixture<GetEvents>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [GetEvents],
    }).compileComponents();

    fixture = TestBed.createComponent(GetEvents);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
