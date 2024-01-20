const ClickMe = () => {
  return (
    <div id="parent-div">
      <button
        hx-post="/clicked"
        hx-trigger="click"
        hx-target="#parent-div"
        hx-swap="outerHTML"
      >
        Click Me!
      </button>
    </div>
  );
};

export default ClickMe;
