import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SubBoughtEventInfo } from './sub-bought-event-info';

describe('SubBoughtEventInfo', () => {
  let component: SubBoughtEventInfo;
  let fixture: ComponentFixture<SubBoughtEventInfo>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SubBoughtEventInfo],
    }).compileComponents();

    fixture = TestBed.createComponent(SubBoughtEventInfo);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
