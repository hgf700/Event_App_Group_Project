import { ComponentFixture, TestBed } from '@angular/core/testing';

import { UserBookmark } from './user-bookmark';

describe('UserBookmark', () => {
  let component: UserBookmark;
  let fixture: ComponentFixture<UserBookmark>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [UserBookmark],
    }).compileComponents();

    fixture = TestBed.createComponent(UserBookmark);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
