import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SearchEvent } from './search-event';

describe('SearchEvent', () => {
  let component: SearchEvent;
  let fixture: ComponentFixture<SearchEvent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SearchEvent],
    }).compileComponents();

    fixture = TestBed.createComponent(SearchEvent);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
