export const usePageContext = () => {
  const dataElement = document.getElementById("__WEB_ROOT_DATA__");
  return JSON.parse(dataElement?.textContent || "{}");
};
